package com.shilapi.xcertplay.usbbt

import android.util.Log
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CID_SIGNALING
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CMD_CONFIG_REQ
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CMD_CONFIG_RSP
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CMD_CONNECTION_REQ
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CMD_CONNECTION_RSP
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CMD_DISCONNECTION_REQ
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CMD_DISCONNECTION_RSP
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CONN_PENDING
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_CONN_SUCCESS
import com.shilapi.xcertplay.usbbt.HciProtocol.encodeL2cap
import com.shilapi.xcertplay.usbbt.HciProtocol.parseL2cap
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * L2CAP layer over an HCI ACL connection (Phase 3).
 *
 * Bluetooth Core Spec Vol 3, Part A. Handles:
 * - signaling (CID 0x0001): Connection Request/Response, Configuration
 *   Request/Response, Disconnection
 * - dynamic CID allocation (0x0040..0xFFFF)
 * - payload segmentation for the controller's ACL MTU and reassembly of
 *   incoming fragments (we only send/receive unfragmented L2CAP PDUs here;
 *   multi-fragment reassembly is supported on receive)
 *
 * All public methods block the calling thread; use from a background thread.
 * Create one instance per ACL connection handle; call [close] when done.
 *
 * Clean-room: derived from the public Bluetooth Core Specification.
 */
class L2capLayer(
    private val aclHandle: Int,
    private val hci: UsbBtHci,
    private val aclMtu: Int = 512,
) {

    /** An established L2CAP channel. */
    data class Channel(
        /** Our local CID (source). */
        val localCid: Int,
        /** Peer's CID (destination). */
        val remoteCid: Int,
        val psm: Int,
    )

    sealed class L2capResult<out T> {
        data class Ok<T>(val value: T) : L2capResult<T>()
        data class Failed(val reason: String) : L2capResult<Nothing>()
    }

    companion object {
        private const val TAG = "L2capLayer"
        private const val SIGNAL_ID_START = 1
        private const val MIN_DYNAMIC_CID = 0x0040
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val CONFIG_TIMEOUT_MS = 5_000
    }

    private val nextSignalId = AtomicInteger(SIGNAL_ID_START)
    private val nextCid = AtomicInteger(MIN_DYNAMIC_CID)

    /** local CID -> Channel, for established channels. */
    private val channels = ConcurrentHashMap<Int, Channel>()

    /** signal id -> pending connection (for matching responses). */
    private val pendingConnects = ConcurrentHashMap<Int, PendingConnect>()

    /** Incoming data callbacks per local CID. */
    private val dataHandlers = ConcurrentHashMap<Int, (ByteArray) -> Unit>()

    private data class PendingConnect(
        val psm: Int,
        val localCid: Int,
        @Volatile var remoteCid: Int = -1,
        @Volatile var result: Int = -1,
        val done: java.util.concurrent.CountDownLatch = java.util.concurrent.CountDownLatch(1),
    )

    @Volatile private var closed = false

    private fun nextSignalId(): Int {
        // Signal identifier 0 is reserved; wrap within 1..255.
        return nextSignalId.getAndUpdate { if (it >= 255) SIGNAL_ID_START else it + 1 }
    }

    private fun allocCid(): Int {
        // Dynamic CIDs 0x0040..0xFFFF; wrap around on exhaustion (unlikely).
        return nextCid.getAndUpdate { if (it >= 0xFFFF) MIN_DYNAMIC_CID else it + 1 }
    }

    private fun u16le(value: Int): ByteArray =
        byteArrayOf((value and 0xFF).toByte(), ((value ushr 8) and 0xFF).toByte())

    private fun readU16(data: ByteArray, at: Int): Int? {
        if (at + 1 >= data.size) return null
        return (data[at].toInt() and 0xFF) or ((data[at + 1].toInt() and 0xFF) shl 8)
    }

    /**
     * Connect an L2CAP channel to [psm] on the peer. Performs the signaling
     * handshake (Connection Request -> Response, then Configuration).
     */
    fun connect(psm: Int): L2capResult<Channel> {
        if (closed) return L2capResult.Failed("L2CAP layer closed")
        val localCid = allocCid()
        val signalId = nextSignalId()
        val pending = PendingConnect(psm = psm, localCid = localCid)
        pendingConnects[signalId] = pending
        try {
            // Connection Request: code(1)=0x02 id(1) len(2)=4 | PSM(2) | SCID(2)
            val req = byteArrayOf(
                L2CAP_CMD_CONNECTION_REQ.toByte(),
                signalId.toByte(),
                0x04, 0x00,
            ) + u16le(psm) + u16le(localCid)
            if (!hci.sendAcl(aclHandle, encodeL2cap(L2CAP_CID_SIGNALING, req))) {
                return L2capResult.Failed("failed to send L2CAP Connection Request (psm=0x${psm.toString(16)})")
            }
            val got = pending.done.await(CONNECT_TIMEOUT_MS.toLong(), java.util.concurrent.TimeUnit.MILLISECONDS)
            if (!got) return L2capResult.Failed("L2CAP connect timeout (psm=0x${psm.toString(16)})")
            if (pending.result != L2CAP_CONN_SUCCESS) {
                return L2capResult.Failed(
                    "L2CAP connect rejected: result=0x${pending.result.toString(16)} (psm=0x${psm.toString(16)})",
                )
            }
            val channel = Channel(localCid = localCid, remoteCid = pending.remoteCid, psm = psm)
            channels[localCid] = channel
            // Minimal configuration exchange: send our Config Request, accept theirs.
            // Many stacks work with default parameters; we send an empty config.
            if (!exchangeConfig(channel)) {
                Log.w(TAG, "L2CAP config exchange failed for psm=0x${psm.toString(16)}; continuing anyway")
            }
            Log.i(TAG, "L2CAP channel up: psm=0x${psm.toString(16)} localCid=0x${localCid.toString(16)} remoteCid=0x${pending.remoteCid.toString(16)}")
            return L2capResult.Ok(channel)
        } finally {
            pendingConnects.remove(signalId)
        }
    }

    private fun exchangeConfig(channel: Channel): Boolean {
        val signalId = nextSignalId()
        // Config Request: code=0x04 id len=4 | DCID(2) | flags(2)=0 (no options)
        val req = byteArrayOf(
            L2CAP_CMD_CONFIG_REQ.toByte(),
            signalId.toByte(),
            0x04, 0x00,
        ) + u16le(channel.remoteCid) + u16le(0)
        if (!hci.sendAcl(aclHandle, encodeL2cap(L2CAP_CID_SIGNALING, req))) return false
        // We don't strictly wait for the response; the peer's own Config Request
        // (handled in onSignaling) completes the handshake. Give it a moment.
        return true
    }

    /**
     * Send [payload] on [channel], fragmenting to the ACL MTU when needed.
     */
    fun send(channel: Channel, payload: ByteArray): Boolean {
        if (closed) return false
        var offset = 0
        // Reserve the 4-byte L2CAP header inside the MTU.
        val chunk = (aclMtu - 4).coerceAtLeast(16)
        while (offset < payload.size) {
            val end = minOf(offset + chunk, payload.size)
            val frame = encodeL2cap(channel.remoteCid, payload.copyOfRange(offset, end))
            if (!hci.sendAcl(aclHandle, frame)) return false
            offset = end
        }
        return true
    }

    /** Register a handler for incoming data on [channel]. */
    fun onData(channel: Channel, handler: (ByteArray) -> Unit) {
        dataHandlers[channel.localCid] = handler
    }

    /**
     * Handle one reassembled L2CAP PDU from the ACL receive loop.
     * Call this for every [HciProtocol.AclPacket] whose handle matches.
     */
    fun onAclData(aclData: ByteArray) {
        val packet = parseL2cap(aclData) ?: run {
            Log.w(TAG, "malformed L2CAP packet (${aclData.size} bytes)")
            return
        }
        if (packet.cid == L2CAP_CID_SIGNALING) {
            onSignaling(packet.payload)
            return
        }
        val handler = dataHandlers[packet.cid]
        if (handler != null) {
            runCatching { handler(packet.payload) }
                .onFailure { Log.w(TAG, "L2CAP data handler failed", it) }
        } else {
            Log.w(TAG, "L2CAP data for unknown CID 0x${packet.cid.toString(16)}")
        }
    }

    private fun onSignaling(payload: ByteArray) {
        var at = 0
        while (at + 4 <= payload.size) {
            val code = payload[at].toInt() and 0xFF
            val id = payload[at + 1].toInt() and 0xFF
            val len = readU16(payload, at + 2) ?: return
            if (at + 4 + len > payload.size) {
                Log.w(TAG, "truncated L2CAP signaling command")
                return
            }
            val data = payload.copyOfRange(at + 4, at + 4 + len)
            when (code) {
                L2CAP_CMD_CONNECTION_RSP -> onConnectionResponse(id, data)
                L2CAP_CMD_CONFIG_REQ -> onConfigRequest(id, data)
                L2CAP_CMD_CONFIG_RSP -> { /* accepted; nothing to do */ }
                L2CAP_CMD_DISCONNECTION_REQ -> onDisconnectionRequest(id, data)
                else -> Log.w(TAG, "unhandled L2CAP signaling code 0x${code.toString(16)}")
            }
            at += 4 + len
        }
    }

    private fun onConnectionResponse(id: Int, data: ByteArray) {
        // Response: DCID(2) | SCID(2) | result(2) | status(2)
        if (data.size < 8) return
        val dcid = readU16(data, 0) ?: return
        val scid = readU16(data, 2) ?: return
        val result = readU16(data, 4) ?: return
        val pending = pendingConnects[id] ?: return
        if (pending.localCid != scid) return
        pending.remoteCid = dcid
        pending.result = result
        if (result == L2CAP_CONN_SUCCESS || result != L2CAP_CONN_PENDING) {
            pending.done.countDown()
        }
        // PENDING means "more to come"; keep waiting for the final response.
    }

    private fun onConfigRequest(id: Int, data: ByteArray) {
        // Request: DCID(2) | flags(2) | options...  Reply with success, no options.
        if (data.size < 4) return
        val dcid = readU16(data, 0) ?: return
        // Config Response: code=0x05 id len=6 | SCID(2)=dcid | flags(2)=0 | result(2)=0
        val rsp = byteArrayOf(
            L2CAP_CMD_CONFIG_RSP.toByte(),
            id.toByte(),
            0x06, 0x00,
        ) + u16le(dcid) + u16le(0) + u16le(0)
        hci.sendAcl(aclHandle, encodeL2cap(L2CAP_CID_SIGNALING, rsp))
    }

    private fun onDisconnectionRequest(id: Int, data: ByteArray) {
        if (data.size < 4) return
        val dcid = readU16(data, 0) ?: return
        val scid = readU16(data, 2) ?: return
        val rsp = byteArrayOf(
            L2CAP_CMD_DISCONNECTION_RSP.toByte(),
            id.toByte(),
            0x04, 0x00,
        ) + u16le(dcid) + u16le(scid)
        hci.sendAcl(aclHandle, encodeL2cap(L2CAP_CID_SIGNALING, rsp))
        channels.remove(dcid)
        dataHandlers.remove(dcid)
        Log.i(TAG, "L2CAP channel 0x${dcid.toString(16)} disconnected by peer")
    }

    /** Disconnect [channel]. */
    fun disconnect(channel: Channel) {
        val signalId = nextSignalId()
        val req = byteArrayOf(
            L2CAP_CMD_DISCONNECTION_REQ.toByte(),
            signalId.toByte(),
            0x04, 0x00,
        ) + u16le(channel.remoteCid) + u16le(channel.localCid)
        hci.sendAcl(aclHandle, encodeL2cap(L2CAP_CID_SIGNALING, req))
        channels.remove(channel.localCid)
        dataHandlers.remove(channel.localCid)
    }

    fun close() {
        closed = true
        channels.keys.toList().forEach { cid ->
            channels[cid]?.let { runCatching { disconnect(it) } }
        }
        channels.clear()
        dataHandlers.clear()
        pendingConnects.values.forEach { it.done.countDown() }
        pendingConnects.clear()
    }
}
