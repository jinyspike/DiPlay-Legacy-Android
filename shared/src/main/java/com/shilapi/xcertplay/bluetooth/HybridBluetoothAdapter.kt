package com.shilapi.xcertplay.bluetooth

import android.content.Context
import android.util.Log
import com.shilapi.xcertplay.transport.BlockingDuplexByteStream
import com.shilapi.xcertplay.usbbt.UsbBtBluetoothAdapter

class HybridBluetoothAdapter(
    val hsae: HsaeBluetoothAdapter,
    val android: AndroidBluetoothAdapter,
    /** USB dongle stack; last resort when neither HSAE nor Android BT exists. */
    val usbDongle: UsbBtBluetoothAdapter? = null,
) : CarPlayBluetooth {

    companion object {
        private const val TAG = "HybridBluetoothAdapter"
    }

    override fun isSupported(): Boolean =
        hsae.isSupported() || android.isSupported() || usbDongle?.isSupported() == true

    override fun isEnabled(): Boolean {
        if (hsae.isSupported() && hsae.isEnabled()) return true
        if (android.isEnabled()) return true
        return usbDongle?.isEnabled() == true
    }

    override fun enable(): Boolean {
        var ok = false
        if (hsae.isSupported()) {
            ok = hsae.enable()
        }
        if (android.enable()) ok = true
        // USB dongle is opt-in via settings; only auto-enable when it is the
        // sole available stack.
        if (!hsae.isSupported() && !android.isSupported()) {
            if (usbDongle?.enable() == true) ok = true
        }
        return ok
    }

    override fun getAdapterName(): String {
        val parts = mutableListOf<String>()
        if (hsae.isSupported()) parts.add("HSAE")
        if (android.isSupported()) parts.add("Android")
        if (usbDongle?.isSupported() == true) parts.add("USB")
        return if (parts.isEmpty()) android.getAdapterName()
        else "Hybrid(${parts.joinToString("+")})"
    }

    override fun getPairedDevices(): List<CarPlayBluetoothDevice> {
        if (hsae.isSupported()) {
            val hsaeList = hsae.getPairedDevices()
            if (hsaeList.isNotEmpty()) return hsaeList
        }
        val androidList = android.getPairedDevices()
        if (androidList.isNotEmpty()) return androidList
        return usbDongle?.getPairedDevices().orEmpty()
    }

    override fun getConnectedDevice(): CarPlayBluetoothDevice? {
        if (hsae.isSupported()) {
            val hsaeConn = hsae.getConnectedDevice()
            if (hsaeConn != null) return hsaeConn
        }
        android.getConnectedDevice()?.let { return it }
        return usbDongle?.getConnectedDevice()
    }

    override fun localAddress(context: Context): String? {
        if (hsae.isSupported()) {
            val hsaeAddr = hsae.localAddress(context)
            if (!hsaeAddr.isNullOrBlank()) return hsaeAddr
        }
        android.localAddress(context)?.let { return it }
        return usbDongle?.localAddress(context)
    }

    override fun openRfcommStream(deviceAddress: String, uuid: String): BlockingDuplexByteStream {
        // Priority: HSAE -> Android -> USB dongle.
        if (hsae.isSupported()) {
            val result = runCatching {
                hsae.openRfcommStream(deviceAddress, uuid)
            }
            val stream = result.getOrNull()
            if (stream != null) return stream
            val hsaeError = result.exceptionOrNull()!!
            Log.w(TAG, "HSAE RFCOMM stream failed, trying Android", hsaeError)
            if (android.isSupported() && android.isEnabled()) {
                return android.openRfcommStream(deviceAddress, uuid)
            }
            usbDongle?.let { dongle ->
                if (dongle.isEnabled()) return dongle.openRfcommStream(deviceAddress, uuid)
            }
            throw hsaeError
        }
        if (android.isSupported()) {
            val result = runCatching {
                android.openRfcommStream(deviceAddress, uuid)
            }
            val stream = result.getOrNull()
            if (stream != null) return stream
            val androidError = result.exceptionOrNull()!!
            Log.w(TAG, "Android RFCOMM stream failed, trying USB dongle", androidError)
            usbDongle?.let { dongle ->
                if (dongle.isEnabled()) return dongle.openRfcommStream(deviceAddress, uuid)
            }
            throw androidError
        }
        val dongle = usbDongle ?: throw java.io.IOException("no Bluetooth stack available")
        return dongle.openRfcommStream(deviceAddress, uuid)
    }
}
