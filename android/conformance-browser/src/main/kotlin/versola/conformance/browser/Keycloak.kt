package versola.conformance.browser

import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import org.json.JSONArray
import org.json.JSONObject

/**
 * The provider's side of the story, read from Keycloak's admin API: whether alice has a
 * sign-in session at the provider. "The SDK says it signed out" is the SDK's word; this is the
 * provider's. The admin credentials are the throwaway ones of
 * `conformance/providers/keycloak/docker-compose.yml`.
 */
internal class Keycloak(
    issuer: String,
    private val adminUser: String,
    private val adminPassword: String,
) {
    private val base = issuer.substringBefore("/realms/")
    private val realm = issuer.substringAfter("/realms/")

    /** Sessions the provider holds for [username]. */
    fun sessions(username: String): Int =
        JSONArray(get("/admin/realms/$realm/users/${userId(username)}/sessions")).length()

    /** Ends every session of [username] at the provider, so a test starts from a signed-out browser. */
    fun endSessions(username: String) {
        request("POST", "/admin/realms/$realm/users/${userId(username)}/logout", null, token())
    }

    private fun userId(username: String): String {
        val users = JSONArray(get("/admin/realms/$realm/users?username=${encode(username)}&exact=true"))
        check(users.length() == 1) { "expected one user named $username in realm $realm" }
        return users.getJSONObject(0).getString("id")
    }

    private fun token(): String {
        val form = "grant_type=password&client_id=admin-cli&username=${encode(adminUser)}&password=${encode(adminPassword)}"
        val response = request("POST", "/realms/master/protocol/openid-connect/token", form, null)
        return JSONObject(response).getString("access_token")
    }

    private fun get(path: String): String = request("GET", path, null, token())

    private fun request(method: String, path: String, form: String?, bearer: String?): String {
        val connection = URL(base + path).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.connectTimeout = TIMEOUT_MILLIS
            connection.readTimeout = TIMEOUT_MILLIS
            bearer?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
            if (form != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                connection.outputStream.use { it.write(form.toByteArray()) }
            } else if (method == "POST") {
                connection.doOutput = true
                connection.outputStream.use { }
            }
            val code = connection.responseCode
            val body = (if (code in 200..299) connection.inputStream else connection.errorStream)
                ?.bufferedReader()?.use { it.readText() }.orEmpty()
            check(code in 200..299) { "$method $path answered $code" }
            return body
        } finally {
            connection.disconnect()
        }
    }

    private fun encode(value: String) = URLEncoder.encode(value, "UTF-8")

    private companion object {
        const val TIMEOUT_MILLIS = 10_000
    }
}
