package com.shilapi.xcertplay.usbbt

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.util.Log
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_CLASS_WIRELESS_CONTROLLER
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_PROTOCOL_BLUETOOTH
import com.shilapi.xcertplay.usbbt.HciProtocol.USB_SUBCLASS_RF

/**
 * Detects USB Bluetooth dongles through the Android USB Host API (Phase 1).
 *
 * A dongle is recognized when either:
 * - the device or one of its interfaces advertises USB class 0xE0 (Wireless
 *   Controller) / subclass 0x01 (RF) / protocol 0x01 (Bluetooth), or
 * - its vendor ID is in the well-known Bluetooth vendor table below.
 *
 * Well-known VIDs are public hardware identifiers (same list every OS USB
 * Bluetooth driver ships); matching by class code is preferred because it
 * also covers unlisted vendors.
 *
 * Clean-room: detection logic derived from the USB-IF class-code documents and
 * public hardware IDs only.
 */
class UsbBtDongleDetector(private val appContext: Context) {

    /** A USB device identified as a Bluetooth dongle. */
    data class Dongle(
        val device: UsbDevice,
        /** Human-readable vendor, e.g. "CSR (0x0a12)". "Unknown" when matched by class code only. */
        val vendorLabel: String,
        /** True when matched via the 0xE0/0x01/0x01 class code rather than the VID table. */
        val viaClassCode: Boolean,
    )

    sealed class PermissionState {
        /** The app already holds USB permission for this device. */
        data object Granted : PermissionState()

        /** A permission request was sent; the caller must handle the broadcast. */
        data object RequestSent : PermissionState()
    }

    companion object {
        private const val TAG = "UsbBtDongleDetector"

        /**
         * Well-known Bluetooth controller vendor IDs. Public hardware identifiers;
         * kept as a fallback for dongles whose descriptors lack the class code.
         */
        val KNOWN_BT_VENDORS: Map<Int, String> = mapOf(
            0x0a12 to "CSR",
            0x0a5c to "Broadcom",
            0x0bda to "Realtek",
            0x8087 to "Intel",
            0x0cf3 to "Atheros",
            0x1286 to "Marvell",
        )

        /** Broadcast action for the USB permission result; host activity routes it. */
        fun permissionAction(packageName: String): String =
            "$packageName${PERMISSION_ACTION_SUFFIX}"

        private const val PERMISSION_ACTION_SUFFIX = ".USB_BT_PERMISSION"
    }

    /**
     * Scan [usbManager] for Bluetooth dongles. Never throws; returns an empty
     * list when the device list is unavailable.
     */
    fun findDongles(usbManager: UsbManager): List<Dongle> {
        val devices = runCatching { usbManager.deviceList.values.toList() }
            .getOrElse {
                Log.w(TAG, "USB device list unavailable", it)
                return emptyList()
            }
        return devices.mapNotNull { device ->
            identify(device)?.also {
                Log.i(
                    TAG,
                    "Bluetooth dongle: vid=0x${device.vendorId.toString(16)} " +
                        "pid=0x${device.productId.toString(16)} vendor=${it.vendorLabel} " +
                        "viaClassCode=${it.viaClassCode}",
                )
            }
        }
    }

    /**
     * Returns null when [device] is not a Bluetooth dongle. The Apple VID is
     * never matched, so an iPhone on the same bus is ignored.
     */
    fun identify(device: UsbDevice): Dongle? {
        if (hasBluetoothClassCode(device)) {
            val vendor = KNOWN_BT_VENDORS[device.vendorId]
            return Dongle(
                device = device,
                vendorLabel = vendor?.let { "$it (0x${device.vendorId.toString(16)})" } ?: "Unknown",
                viaClassCode = true,
            )
        }
        val vendor = KNOWN_BT_VENDORS[device.vendorId] ?: return null
        return Dongle(
            device = device,
            vendorLabel = "$vendor (0x${device.vendorId.toString(16)})",
            viaClassCode = false,
        )
    }

    private fun hasBluetoothClassCode(device: UsbDevice): Boolean {
        if (isBluetoothClass(device.deviceClass, device.deviceSubClass, device.deviceProtocol)) {
            return true
        }
        for (i in 0 until device.interfaceCount) {
            val intf = device.getInterface(i)
            if (isBluetoothClass(intf.interfaceClass, intf.interfaceSubclass, intf.interfaceProtocol)) {
                return true
            }
        }
        return false
    }

    private fun isBluetoothClass(classCode: Int, subClass: Int, protocol: Int): Boolean =
        classCode == USB_CLASS_WIRELESS_CONTROLLER &&
            subClass == USB_SUBCLASS_RF &&
            protocol == USB_PROTOCOL_BLUETOOTH

    /**
     * Ensure USB permission for [dongle]. Returns [PermissionState.Granted] when
     * the app can open the device now, [PermissionState.RequestSent] when the
     * user must confirm the system dialog first.
     */
    fun ensurePermission(usbManager: UsbManager, dongle: Dongle): PermissionState {
        if (usbManager.hasPermission(dongle.device)) return PermissionState.Granted
        val intent = Intent(permissionAction(appContext.packageName))
            .setPackage(appContext.packageName)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
        val pi = PendingIntent.getBroadcast(appContext, 0, intent, flags)
        usbManager.requestPermission(dongle.device, pi)
        return PermissionState.RequestSent
    }
}
