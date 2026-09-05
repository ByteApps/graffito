package com.byteapps.graffito;

import android.app.Application;

/**
 * The one Java class in the Play build, and it exists for exactly one reason:
 * Play's "Automatic protection — Prevent unofficial installs" (Protected with
 * Play) rewrites every uploaded bundle at upload time, injecting its own
 * classes.dex and pointing android:name at com.pairip.application.Application,
 * which wraps the app's declared Application class. A NativeActivity-only app
 * with android:hasCode="false" and no Application class gives it nothing to
 * wrap AND tells ART to load no dex at all, so the Play-served copy died on
 * every launch with ClassNotFoundException: com.pairip.application.Application
 * (versionCode 9, 2026-09-04, Pixel 11 Pro XL / Android 17). Emulators never
 * showed it because they run OUR bundle, not Play's re-signed one.
 *
 * This class does nothing; all app code is Rust (NativeActivity + the
 * in-memory BiometricPrompt dex). Keep it empty and keep android:hasCode
 * OFF the manifest (i.e. default true) so the injected dex is loaded.
 */
public class GraffitoApplication extends Application {
}
