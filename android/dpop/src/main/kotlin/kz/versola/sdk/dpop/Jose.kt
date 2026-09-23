package kz.versola.sdk.dpop

import java.math.BigInteger
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.Base64

/**
 * The JOSE encodings a DPoP proof needs, and nothing else.
 *
 * `:core` has an equivalent `Base64Url`, deliberately not shared: it is `internal` there, and
 * publishing an encoding helper on the protocol module's ABI to save four lines here would be
 * a worse trade than the duplication.
 */
internal object Jose {

    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

    /** P-256 field elements and ECDSA signature components are 32 bytes each, always. */
    const val P256_COMPONENT_BYTES: Int = 32

    fun base64Url(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    /**
     * The public key as a JWK in RFC 7638 §3.3 canonical form: required members only, no
     * whitespace, lexicographic order.
     *
     * Returned as a string rather than a structure because it is used twice — embedded in the
     * proof header and hashed into the thumbprint — and those two must be the same bytes. A
     * canonical form rebuilt separately for each is exactly how a `jkt` comes to disagree with
     * the key it names.
     */
    fun canonicalJwk(key: ECPublicKey): String {
        val x = base64Url(fixedWidth(key.w.affineX, P256_COMPONENT_BYTES))
        val y = base64Url(fixedWidth(key.w.affineY, P256_COMPONENT_BYTES))
        return """{"crv":"P-256","kty":"EC","x":"$x","y":"$y"}"""
    }

    /** RFC 7638 §3.4: base64url of the SHA-256 over exactly the [canonicalJwk] bytes. */
    fun thumbprint(canonicalJwk: String): String =
        base64Url(sha256(canonicalJwk.toByteArray(Charsets.UTF_8)))

    /**
     * Converts an X9.62 DER `SEQUENCE { INTEGER r, INTEGER s }` — what the JCA and the Android
     * Keystore emit — into the fixed-width `R‖S` concatenation JWS requires (RFC 7515 §A.3).
     *
     * This conversion is the classic source of intermittent DPoP failures: it only misbehaves
     * when `r` or `s` happens to have a leading zero byte or a high bit set, which is roughly
     * one signature in every few hundred, so a naive implementation passes every manual test
     * and fails in production.
     */
    fun derToJose(der: ByteArray, componentBytes: Int = P256_COMPONENT_BYTES): ByteArray {
        var offset = 0
        require(der.size >= 8 && der[offset].toInt() == 0x30) { "DPoP signature is not a DER SEQUENCE" }
        offset++
        var sequenceLength = der[offset].toInt() and 0xff
        offset++
        if (sequenceLength and 0x80 != 0) {
            // Long-form length. A P-256 signature never needs one, but reading it is cheaper
            // than a silent misparse if a provider ever returns something larger.
            var lengthBytes = sequenceLength and 0x7f
            sequenceLength = 0
            while (lengthBytes-- > 0) {
                sequenceLength = (sequenceLength shl 8) or (der[offset].toInt() and 0xff)
                offset++
            }
        }
        val (r, afterR) = readInteger(der, offset)
        val (s, afterS) = readInteger(der, afterR)
        require(afterS == der.size) { "DPoP signature carries trailing bytes after r and s" }
        return fixedWidth(r, componentBytes) + fixedWidth(s, componentBytes)
    }

    private fun readInteger(der: ByteArray, start: Int): Pair<ByteArray, Int> {
        require(start + 2 <= der.size && der[start].toInt() == 0x02) {
            "DPoP signature component is not a DER INTEGER"
        }
        val length = der[start + 1].toInt() and 0xff
        val from = start + 2
        require(from + length <= der.size) { "DPoP signature component runs past the end" }
        return der.copyOfRange(from, from + length) to from + length
    }

    private fun fixedWidth(value: BigInteger, width: Int): ByteArray = fixedWidth(value.toByteArray(), width)

    /**
     * Left-pads to [width], having dropped the sign byte a DER INTEGER carries when its top
     * bit would otherwise read as negative. Both directions matter: a 33-byte value is one
     * byte too long and a 31-byte value one byte too short, and each produces a signature the
     * server rejects.
     */
    private fun fixedWidth(value: ByteArray, width: Int): ByteArray {
        var from = 0
        while (from < value.size - 1 && value[from] == 0.toByte()) from++
        val significant = value.size - from
        require(significant <= width) { "value is $significant bytes, wider than the $width JOSE expects" }
        val padded = ByteArray(width)
        value.copyInto(padded, width - significant, from)
        return padded
    }
}
