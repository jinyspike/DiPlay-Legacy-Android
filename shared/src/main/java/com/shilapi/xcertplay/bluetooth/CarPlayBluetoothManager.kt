package com.shilapi.xcertplay.bluetooth

import android.content.Context
import com.shilapi.xcertplay.usbbt.UsbBtBluetoothAdapter

object CarPlayBluetoothManager {
    @Volatile
    private var instance: HybridBluetoothAdapter? = null

    fun get(context: Context): HybridBluetoothAdapter {
        return instance ?: synchronized(this) {
            instance ?: HybridBluetoothAdapter(
                HsaeBluetoothAdapter(context.applicationContext),
                AndroidBluetoothAdapter(context.applicationContext),
                // USB dongle stack: constructed lazily; enable() is opt-in and
                // only auto-runs when no other stack exists (see Hybrid).
                UsbBtBluetoothAdapter(context.applicationContext),
            ).also { instance = it }
        }
    }
}
