package xyz.foundation.graffito;

import android.app.Activity;
import android.view.WindowManager;

/**
 * FLAG_SECURE on/off for the activity window — screenshots, screen
 * recording and the recents thumbnail all go black while a secret is on
 * screen (Private keys reveal, backup words, the quantum private-key
 * backup). Window flags must be touched on the UI thread, so this is a
 * Runnable that Rust posts through Activity.runOnUiThread; it rides in the
 * same in-memory dex as BiometricBridge (scripts/gen-biometric-dex.sh
 * compiles every .java in this directory).
 */
public final class WindowSecure implements Runnable {
    private final Activity activity;
    private final boolean secure;

    public WindowSecure(Activity activity, boolean secure) {
        this.activity = activity;
        this.secure = secure;
    }

    @Override
    public void run() {
        if (secure) {
            activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        } else {
            activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        }
    }
}
