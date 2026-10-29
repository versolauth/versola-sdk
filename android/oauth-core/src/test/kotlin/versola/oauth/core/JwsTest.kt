package versola.oauth.core

import java.security.KeyPair
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class JwsTest {

    private val payload = """{"sub":"u1"}"""

    private fun rejection(compact: String): IdTokenRejection =
        try {
            Jws.parse(compact)
            fail("expected a rejection")
            error("unreachable")
        } catch (e: JwsRejection) {
            e.reason
        }

    private fun verifies(alg: String, signer: KeyPair, verifier: KeyPair = signer): Boolean {
        val token = Jws.parse(Jose.jws(alg, signer.private, payload, kid = "k"))
        return Jws.verify(token, verifier.public, JwsAlgorithm.forName(alg)!!)
    }

    @Test
    fun `a compact JWS is split into header, payload and signature with alg, kid and typ read`() {
        val token = Jws.parse(Jose.jws("RS256", Jose.rsa.private, payload, kid = "k1"))

        assertEquals("RS256", token.alg)
        assertEquals("k1", token.kid)
        assertEquals("JWT", token.typ)
        assertEquals("u1", (token.payload["sub"] as kotlinx.serialization.json.JsonPrimitive).content)
    }

    @Test
    fun `a token with two segments is malformed`() {
        assertEquals(IdTokenRejection.Malformed, rejection("aaa.bbb"))
    }

    @Test
    fun `a token with four segments is malformed`() {
        assertEquals(IdTokenRejection.Malformed, rejection("a.b.c.d"))
    }

    @Test
    fun `a segment that is not base64url is malformed`() {
        assertEquals(IdTokenRejection.Malformed, rejection("!!!." + Jose.b64(payload) + ".AAAA"))
    }

    @Test
    fun `a header that is not JSON is malformed`() {
        assertEquals(IdTokenRejection.Malformed, rejection(Jose.b64("not json") + "." + Jose.b64(payload) + ".AAAA"))
    }

    @Test
    fun `a payload that is not a JSON object is malformed`() {
        assertEquals(IdTokenRejection.Malformed, rejection(Jose.b64("""{"alg":"RS256"}""") + "." + Jose.b64("[1]") + ".AAAA"))
    }

    @Test
    fun `a header without a string alg is malformed`() {
        assertEquals(IdTokenRejection.Malformed, rejection(Jose.b64("""{"alg":5}""") + "." + Jose.b64(payload) + ".AAAA"))
    }

    @Test
    fun `a header with a crit extension is refused because none is understood`() {
        val header = """{"alg":"RS256","crit":["exp"],"exp":1}"""
        assertEquals(IdTokenRejection.Malformed, rejection(Jose.jws("RS256", Jose.rsa.private, payload, header = header)))
    }

    @Test
    fun `RS256 RS384 and RS512 signatures verify under the RSA key`() {
        for (alg in listOf("RS256", "RS384", "RS512")) assertTrue(alg, verifies(alg, Jose.rsa))
    }

    @Test
    fun `PS256 PS384 and PS512 signatures verify under the RSA key`() {
        for (alg in listOf("PS256", "PS384", "PS512")) assertTrue(alg, verifies(alg, Jose.rsa))
    }

    @Test
    fun `ES256 ES384 and ES512 signatures verify under the P-256 P-384 and P-521 keys`() {
        assertTrue(verifies("ES256", Jose.p256))
        assertTrue(verifies("ES384", Jose.p384))
        assertTrue(verifies("ES512", Jose.p521))
    }

    @Test
    fun `many ES256 signatures verify whatever their leading zeros and high bits`() {
        // R and S are random 256-bit integers; about one in 128 has a leading zero byte and
        // half have the top bit set, the two shapes a DER conversion gets wrong.
        repeat(300) { assertTrue(verifies("ES256", Jose.p256)) }
    }

    @Test
    fun `a signature made by another RSA key does not verify`() {
        assertFalse(verifies("RS256", Jose.rsa, Jose.rsaOther))
    }

    @Test
    fun `a signature made by another EC key does not verify`() {
        assertFalse(verifies("ES256", Jose.p256, Jose.p256Other))
    }

    @Test
    fun `a payload changed after signing does not verify`() {
        val good = Jose.jws("RS256", Jose.rsa.private, payload)
        val parts = good.split('.')
        val tampered = parts[0] + "." + Jose.b64("""{"sub":"u2"}""") + "." + parts[2]

        assertFalse(Jws.verify(Jws.parse(tampered), Jose.rsa.public, JwsAlgorithm.RS256))
    }

    @Test
    fun `an RS256 signature does not verify as PS256 and the reverse`() {
        val rs = Jws.parse(Jose.jws("RS256", Jose.rsa.private, payload))
        val ps = Jws.parse(Jose.jws("PS256", Jose.rsa.private, payload))

        assertFalse(Jws.verify(rs, Jose.rsa.public, JwsAlgorithm.PS256))
        assertFalse(Jws.verify(ps, Jose.rsa.public, JwsAlgorithm.RS256))
    }

    @Test
    fun `ES256 does not verify with a P-384 key nor RS256 with an EC key`() {
        val es = Jws.parse(Jose.jws("ES256", Jose.p256.private, payload))
        val rs = Jws.parse(Jose.jws("RS256", Jose.rsa.private, payload))

        assertFalse(Jws.verify(es, Jose.p384.public, JwsAlgorithm.ES256))
        assertFalse(Jws.verify(rs, Jose.p256.public, JwsAlgorithm.RS256))
        assertFalse(Jws.verify(es, Jose.rsa.public, JwsAlgorithm.ES256))
    }

    @Test
    fun `an ES256 signature of the wrong length does not verify`() {
        val good = Jose.jws("ES256", Jose.p256.private, payload).split('.')
        val short = good[0] + "." + good[1] + "." + Jose.b64(ByteArray(63))

        assertFalse(Jws.verify(Jws.parse(short), Jose.p256.public, JwsAlgorithm.ES256))
    }

    @Test
    fun `an R and S of zeros does not verify`() {
        val good = Jose.jws("ES256", Jose.p256.private, payload).split('.')
        val zero = good[0] + "." + good[1] + "." + Jose.b64(ByteArray(64))

        assertFalse(Jws.verify(Jws.parse(zero), Jose.p256.public, JwsAlgorithm.ES256))
    }

    @Test
    fun `an RSA key under 2048 bits is not suitable for any RSA algorithm`() {
        val small = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val token = Jws.parse(Jose.jws("RS256", small.private, payload))

        assertFalse(Jws.verify(token, small.public, JwsAlgorithm.RS256))
    }

    @Test
    fun `JOSE to DER keeps leading zeros out and puts a zero byte in front of a high bit`() {
        // R = 1 (31 leading zero bytes), S = 0x80 00 .. 00 (top bit set).
        val r = ByteArray(32).also { it[31] = 1 }
        val s = ByteArray(32).also { it[0] = 0x80.toByte() }

        val der = Jws.joseToDer(r + s, 32)!!

        val expected = byteArrayOf(0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, 0x80.toByte()) + ByteArray(31)
        assertArrayEquals(expected, der)
    }

    @Test
    fun `JOSE to DER uses the long length form for P-521`() {
        val high = ByteArray(66) { 0xFF.toByte() }

        val der = Jws.joseToDer(high + high, 66)!!

        // Two integers of 0x00 + 66 bytes, each with a 2-byte header: 2 * 69 = 138 = 0x8A.
        assertArrayEquals(byteArrayOf(0x30, 0x81.toByte(), 0x8A.toByte(), 0x02, 0x43, 0x00), der.copyOfRange(0, 6))
        assertEquals(3 + 138, der.size)
    }

    @Test
    fun `JOSE to DER of a zero component is the single byte zero`() {
        val der = Jws.joseToDer(ByteArray(64), 32)!!

        assertArrayEquals(byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00), der)
    }

    @Test
    fun `JOSE to DER of the wrong total length is null`() {
        assertNull(Jws.joseToDer(ByteArray(63), 32))
        assertNull(Jws.joseToDer(ByteArray(65), 32))
    }

    @Test
    fun `none and the HMAC algorithms are not in the algorithm set`() {
        for (name in listOf("none", "HS256", "HS384", "HS512", "RS1", "ES256K", "EdDSA", "rs256")) {
            assertNull(name, JwsAlgorithm.forName(name))
        }
    }
}
