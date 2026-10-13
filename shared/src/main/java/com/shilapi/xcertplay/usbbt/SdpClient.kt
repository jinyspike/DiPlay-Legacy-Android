package com.shilapi.xcertplay.usbbt

import android.util.Log
import com.shilapi.xcertplay.usbbt.HciProtocol.IAP2_UUID_BYTES
import com.shilapi.xcertplay.usbbt.HciProtocol.L2CAP_PSM_SDP
import com.shilapi.xcertplay.usbbt.HciProtocol.SDP_PDU_SERVICE_SEARCH_ATTR_REQ
import com.shilapi.xcertplay.usbbt.HciProtocol.SDP_PDU_SERVICE_SEARCH_ATTR_RSP
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * SDP client over L2CAP (Phase 3).
 *
 * Bluetooth Core Spec Vol 3, Part B. Queries the peer for the iAP2 service
 * and extracts its RFCOMM server channel from the Protocol Descriptor List
 * (attribute 0x0004).
 *
 * All public methods block the calling thread; use from a background thread.
 *
 * Clean-room: derived from the public Bluetooth Core Specification.
 */
class SdpClient(
    private val l2cap: L2capLayer,
    private val aclHandle: Int,
) {

    sealed class SdpResult<out T> {
        data class Ok<T>(val value: T) : SdpResult<T>()
        data class Failed(val reason: String) : SdpResult<Nothing>()
    }

    companion object {
        private const val TAG = "SdpClient"
        private const val QUERY_TIMEOUT_MS = 8_000L

        /** SDP attribute: Protocol Descriptor List. */
        private const val ATTR_PROTOCOL_DESCRIPTOR_LIST = 0x0004

        /** Well-known UUIDs (16-bit, big-endian on the wire). */
        private const val UUID_L2CAP = 0x0100
        private const val UUID_RFCOMM = 0x0003
    }

    private val nextTransactionId = AtomicInteger(1)
    private val responses = LinkedBlockingQueue<ByteArray>(8)
    @Volatile private var channel: L2capLayer.Channel? = null
    @Volatile private var closed = false

    /**
     * Query the peer's iAP2 service and return its RFCOMM server channel,
     * or a failure. Opens (and keeps) the SDP L2CAP channel for reuse.
     */
    fun findIap2RfcommChannel(): SdpResult<Int> {
        val ch = ensureChannel() ?: return SdpResult.Failed("SDP L2CAP channel failed")
        val tid = nextTransactionId.getAndUpdate { if (it >= 0xFFFF) 1 else it + 1 }
        val request = buildSearchAttrRequest(tid)
        if (!l2cap.send(ch, request)) {
            return SdpResult.Failed("failed to send SDP request")
        }
        val deadline = System.currentTimeMillis() + QUERY_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline && !closed) {
            val remaining = deadline - System.currentTimeMillis()
            val pdu = responses.poll(remaining.coerceAtMost(1_000), TimeUnit.MILLISECONDS)
                ?: continue
            val parsed = parseResponse(pdu, tid) ?: continue
            return when (val channelNum = extractRfcommChannel(parsed)) {
                null -> SdpResult.Failed("iAP2 service found but no RFCOMM channel in descriptor list")
                else -> {
                    Log.i(TAG, "iAP2 RFCOMM channel=$channelNum")
                    SdpResult.Ok(channelNum)
                }
            }
        }
        return SdpResult.Failed("SDP query timeout")
    }

    private fun ensureChannel(): L2capLayer.Channel? {
        channel?.let { return it }
        if (closed) return null
        return when (val r = l2cap.connect(L2CAP_PSM_SDP)) {
            is L2capLayer.L2capResult.Ok -> {
                l2cap.onData(r.value) { payload -> onSdpPdu(payload) }
                channel = r.value
                r.value
            }
            is L2capLayer.L2capResult.Failed -> {
                Log.w(TAG, "SDP L2CAP connect failed: ${r.reason}")
                null
            }
        }
    }

    private fun onSdpPdu(payload: ByteArray) {
        if (payload.isNotEmpty()) {
            responses.offer(payload)
        }
    }

    // ------------------------------------------------------------------
    // Request building.
    // ------------------------------------------------------------------

    /**
     * Service Search Attribute Request for the iAP2 128-bit UUID, asking only
     * for the Protocol Descriptor List attribute.
     */
    private fun buildSearchAttrRequest(transactionId: Int): ByteArray {
        // ServiceSearchPattern: DES (0x35) len | UUID128 (0x1C) + 16 bytes
        val searchPattern = byteArrayOf(0x35, 0x13, 0x1C) + IAP2_UUID_BYTES
        // AttributeIDList: DES (0x35) len=3 | UINT16 (0x09) 0x0004
        val attrList = byteArrayOf(0x35, 0x03, 0x09, 0x00, 0x04)
        val params = searchPattern +
            byteArrayOf(0xFF.toByte(), 0xFF.toByte()) + // max attribute bytes = 65535
            attrList +
            byteArrayOf(0x00) // continuation state: none
        return byteArrayOf(SDP_PDU_SERVICE_SEARCH_ATTR_REQ.toByte()) +
            byteArrayOf(((transactionId ushr 8) and 0xFF).toByte(), (transactionId and 0xFF).toByte()) +
            byteArrayOf(((params.size ushr 8) and 0xFF).toByte(), (params.size and 0xFF).toByte()) +
            params
    }

    // ------------------------------------------------------------------
    // Response parsing (minimal DES parser, bounds-checked).
    // ------------------------------------------------------------------

    private data class ParsedResponse(val attributeLists: ByteArray)

    private fun parseResponse(pdu: ByteArray, wantTid: Int): ParsedResponse? {
        if (pdu.size < 5) return null
        if (pdu[0].toInt() and 0xFF != SDP_PDU_SERVICE_SEARCH_ATTR_RSP) return null
        val tid = ((pdu[1].toInt() and 0xFF) shl 8) or (pdu[2].toInt() and 0xFF)
        if (tid != wantTid) return null
        val paramLen = ((pdu[3].toInt() and 0xFF) shl 8) or (pdu[4].toInt() and 0xFF)
        if (5 + paramLen > pdu.size) return null
        // Params: AttributeListsByteCount(2) | lists | ContinuationState
        if (paramLen < 2) return null
        val listLen = ((pdu[5].toInt() and 0xFF) shl 8) or (pdu[6].toInt() and 0xFF)
        if (7 + listLen > 5 + paramLen) return null
        return ParsedResponse(attributeLists = pdu.copyOfRange(7, 7 + listLen))
    }

    /**
     * Walk the attribute list DES, find attribute 0x0004, then walk its
     * Protocol Descriptor List to find the RFCOMM entry's channel byte.
     */
    private fun extractRfcommChannel(parsed: ParsedResponse): Int? {
        val lists = parsed.attributeLists
        // Outer: DES of attribute lists.
        val outer = readDes(lists, 0) ?: return null
        var at = outer.contentStart
        val outerEnd = outer.contentStart + outer.contentLength
        while (at < outerEnd) {
            // Each attribute list is a DES of (id, value) pairs.
            val attrList = readDes(lists, at) ?: return null
            var inner = attrList.contentStart
            val innerEnd = attrList.contentStart + attrList.contentLength
            while (inner < innerEnd) {
                // Attribute ID: UINT16 (0x09)
                if (lists[inner].toInt() and 0xFF != 0x09 || inner + 3 > innerEnd) break
                val attrId = ((lists[inner + 1].toInt() and 0xFF) shl 8) or
                    (lists[inner + 2].toInt() and 0xFF)
                inner += 3
                val valueDes = readDes(lists, inner) ?: return null
                if (attrId == ATTR_PROTOCOL_DESCRIPTOR_LIST) {
                    findRfcommInPdl(lists, valueDes)?.let { return it }
                }
                inner = valueDes.contentStart + valueDes.contentLength
            }
            at = attrList.contentStart + attrList.contentLength
        }
        return null
    }

    /** Inside the Protocol Descriptor List, find [UUID_RFCOMM, channel]. */
    private fun findRfcommInPdl(data: ByteArray, pdl: Des): Int? {
        var at = pdl.contentStart
        val end = pdl.contentStart + pdl.contentLength
        while (at < end) {
            // Each protocol entry is a DES: [ UUID16, params... ]
            val entry = readDes(data, at) ?: return null
            var inner = entry.contentStart
            val entryEnd = entry.contentStart + entry.contentLength
            // First element should be the protocol UUID (UINT16 0x09).
            if (inner + 3 <= entryEnd && data[inner].toInt() and 0xFF == 0x09) {
                val uuid = ((data[inner + 1].toInt() and 0xFF) shl 8) or
                    (data[inner + 2].toInt() and 0xFF)
                if (uuid == UUID_RFCOMM) {
                    // Next element should be UINT8 channel (0x08).
                    inner += 3
                    if (inner + 2 <= entryEnd && data[inner].toInt() and 0xFF == 0x08) {
                        return data[inner + 1].toInt() and 0xFF
                    }
                    return null
                }
            }
            at = entry.contentStart + entry.contentLength
        }
        return null
    }

    /** A parsed Data Element Sequence header. */
    private data class Des(val contentStart: Int, val contentLength: Int)

    /**
     * Parse a DES header (0x35) at [at]. Returns null when malformed.
     * Supports 1-byte and 2-byte length forms.
     */
    private fun readDes(data: ByteArray, at: Int): Des? {
        if (at >= data.size) return null
        if (data[at].toInt() and 0xFF != 0x35) return null
        if (at + 1 >= data.size) return null
        val lenByte = data[at + 1].toInt() and 0xFF
        val (length, headerSize) = when {
            lenByte and 0x80 == 0 -> lenByte to 2
            else -> {
                // Long form: lower 7 bits = extra length bytes (we support 1).
                val extra = lenByte and 0x7F
                if (extra != 1 || at + 2 >= data.size) return null
                (data[at + 2].toInt() and 0xFF) to 3
            }
        }
        val start = at + headerSize
        if (start + length > data.size) return null
        return Des(contentStart = start, contentLength = length)
    }

    fun close() {
        closed = true
        channel?.let { runCatching { l2cap.disconnect(it) } }
        channel = null
        responses.clear()
    }
}
