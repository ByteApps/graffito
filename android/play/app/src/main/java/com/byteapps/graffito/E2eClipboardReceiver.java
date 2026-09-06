package com.byteapps.graffito;

import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;

/**
 * Test hook: puts a string on the system clipboard so an automation harness
 * can paste long text (a quantum public key armor, ~2 KB of mixed-case
 * base64) into a field — `adb shell input text` scrambles mixed-case input
 * on the Slint text field, and Android offers no adb clipboard command.
 *
 *   adb shell am broadcast -a com.byteapps.graffito.SET_CLIPBOARD \
 *       -n com.byteapps.graffito/.E2eClipboardReceiver --es text '...'
 *
 * Guarded in the manifest by android.permission.INJECT_EVENTS, which only
 * the shell (adb) and the system hold — no third-party app can trigger it.
 * It writes the SYSTEM clipboard, nothing app-internal.
 */
public final class E2eClipboardReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !"com.byteapps.graffito.SET_CLIPBOARD".equals(intent.getAction())) return;
        String text = intent.getStringExtra("text");
        if (text == null) return;
        ClipboardManager cm = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("e2e", text));
    }
}
