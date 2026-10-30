package versola.oauth.core

import okhttp3.Headers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ClockSkewDateTest {

    private val date = "Tue, 14 Nov 2023 22:13:20 GMT"

    @Test
    fun `a response without an Age, or with Age 0, offers its Date to the clock`() {
        assertEquals(date, Headers.headersOf("Date", date).dateForClockSkew())
        assertEquals(date, Headers.headersOf("Date", date, "Age", "0").dateForClockSkew())
        assertEquals(date, Headers.headersOf("Date", date, "Age", " 0 ").dateForClockSkew())
    }

    @Test
    fun `a response that sat in a cache offers nothing`() {
        // Its Date is when the origin made it, not now: RFC 9111 section 5.1.
        assertNull(Headers.headersOf("Date", date, "Age", "3600").dateForClockSkew())
        assertNull(Headers.headersOf("Date", date, "Age", "garbage").dateForClockSkew())
    }

    @Test
    fun `no Date offers nothing`() {
        assertNull(Headers.headersOf("Age", "0").dateForClockSkew())
    }
}
