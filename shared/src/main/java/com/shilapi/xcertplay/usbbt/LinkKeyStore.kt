package com.shilapi.xcertplay.usbbt

import android.content.Context
import android.util.Log
import androidx.core.content.edit

/**
 * Persistent store for Bluetooth link keys (Phase 4).
 *
 * Keys are indexed by peer BD_ADDR ("XX:XX:XX:XX:XX:XX"). Stored as hex in
 * SharedPreferences; never logged.
 *
 * Clean-room: standard Android persistence, no protocol specifics.
 */
class LinkKeyStore(appContext: Context) {

    companion object {
        private const val TAG = "LinkKeyStore"
        private const val PREFS = "usbbt_linkkeys"
        private const val KEY_PREFIX = "lk_"
    }

    private val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Store the 16-byte link key for [bdAddr]. */
    fun store(bdAddr: String, linkKey: ByteArray) {
        if (linkKey.size != 16) {
            Log.w(TAG, "refusing to store malformed link key (${linkKey.size} bytes)")
            return
        }
        val hex = linkKey.joinToString("") { "%02x".format(it) }
        prefs.edit { putString(KEY_PREFIX + bdAddr.uppercase(), hex) }
        Log.i(TAG, "link key stored for $bdAddr")
    }

    /** Load the link key for [bdAddr], or null when absent/malformed. */
    fun load(bdAddr: String): ByteArray? {
        val hex = prefs.getString(KEY_PREFIX + bdAddr.uppercase(), null) ?: return null
        if (hex.length != 32) return null
        return runCatching {
            ByteArray(16) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        }.getOrNull()
    }

    /** Forget the link key for [bdAddr]. */
    fun forget(bdAddr: String) {
        prefs.edit { remove(KEY_PREFIX + bdAddr.uppercase()) }
    }

    /** All stored peer addresses. */
    fun peers(): Set<String> {
        return prefs.all.keys
            .filter { it.startsWith(KEY_PREFIX) }
            .map { it.removePrefix(KEY_PREFIX) }
            .toSet()
    }
}
