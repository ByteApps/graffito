package xyz.foundation.chainnotes;

import android.app.Activity;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/**
 * Everything JNI cannot build for itself, in one class.
 *
 * Three of the pieces BiometricPrompt needs cannot be created from JNI:
 * AuthenticationCallback is an ABSTRACT CLASS (so reflect.Proxy, which handles
 * interfaces only, cannot make one), and while Runnable and Executor ARE
 * interfaces, Proxy still needs an InvocationHandler implementation — the same
 * problem one level down. So this single class is the callback, the Runnable
 * posted to the UI thread, and the Executor the callbacks arrive on.
 *
 * Compiled with javac + d8 into a standalone dex that is EMBEDDED IN THE RUST
 * BINARY and loaded at runtime via InMemoryDexClassLoader over a direct
 * ByteBuffer (API 26 = this app's min_sdk). No asset packaging, and no Gradle.
 *
 * The result comes back through a CountDownLatch, so there is no RegisterNatives
 * plumbing: Rust constructs an instance, posts it with runOnUiThread, then
 * blocks in await() on the native thread android_main runs on. Blocking there
 * is safe — it is NOT the Java main thread, so the ANR watchdog is unaffected
 * and the prompt stays responsive.
 *
 * DEFAULT IS DENIAL: `result` starts at ERROR, so every path that fails to
 * complete — timeout, an exception before authenticate(), a cancelled signal —
 * reads as "not authenticated" rather than as success.
 */
public final class BiometricBridge extends BiometricPrompt.AuthenticationCallback
        implements Runnable, Executor, android.content.DialogInterface.OnClickListener {

    public static final int SUCCEEDED = 1;
    public static final int FAILED = 2;   // presented and rejected
    public static final int ERROR = 3;    // cancelled, lockout, no hardware, timeout

    public volatile int result = ERROR;
    public volatile int errorCode = -1;

    private final CountDownLatch latch = new CountDownLatch(1);
    private final Activity activity;
    private final String title;
    private final String subtitle;
    private final String negative;

    public BiometricBridge(Activity activity, String title, String subtitle, String negative) {
        this.activity = activity;
        this.title = title;
        this.subtitle = subtitle;
        this.negative = negative;
    }

    /** Posted to the UI thread; builds and shows the prompt. */
    @Override
    public void run() {
        try {
            BiometricPrompt prompt = new BiometricPrompt.Builder(activity)
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    // A negative button is MANDATORY before API 30 (the builder
                    // throws without one), and it is also the user's way out.
                    // `this` as the listener rather than a lambda: compiling
                    // against android.jar at -source 8 has no LambdaMetafactory,
                    // so a lambda fails to compile here.
                    .setNegativeButton(negative, this, this)
                    .build();
            prompt.authenticate(new CancellationSignal(), this, this);
        } catch (Throwable t) {
            // Never leave the waiter hanging: a builder/permission failure is a
            // denial, not a hang.
            result = ERROR;
            latch.countDown();
        }
    }

    /** The negative button — the user's way out, and a denial. */
    @Override
    public void onClick(android.content.DialogInterface dialog, int which) {
        result = ERROR;
        latch.countDown();
    }

    /** Executor: run inline. The callbacks only touch volatile fields + latch. */
    @Override
    public void execute(Runnable r) {
        r.run();
    }

    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
        result = SUCCEEDED;
        latch.countDown();
    }

    /** Terminal: the OS gave up (cancel, lockout, nothing enrolled). */
    @Override
    public void onAuthenticationError(int code, CharSequence message) {
        errorCode = code;
        result = ERROR;
        latch.countDown();
    }

    /**
     * NOT terminal — a finger did not match and the prompt stays up for another
     * try. Deliberately does not count down: doing so would end the wait on the
     * first bad read while the user is still trying.
     */
    @Override
    public void onAuthenticationFailed() {
        // no-op by design
    }

    /** Blocks up to timeoutMs. ERROR on timeout. */
    public int await(long timeoutMs) {
        try {
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                return ERROR;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ERROR;
        }
        return result;
    }
}
