package kz.versola.sdk.okhttp

/**
 * The `WWW-Authenticate` parameters a 401 from edge carries, read **by parameter name and
 * never by scheme**.
 *
 * The scheme is not a reliable discriminator and reading it is the documented way to get this
 * wrong (`spec/errors.md`): `EdgeService` builds `insufficient_user_authentication` under
 * `Bearer` while using `DPoP` for `invalid_dpop_proof` and `use_dpop_nonce`. A client keyed on
 * the scheme misses every step-up, and one that reads a `Bearer` challenge on a DPoP-bound
 * session as a downgrade attack refuses a legitimate response.
 */
internal class AuthenticateChallenge(
    val error: String?,
    val acrValues: List<String>,
    val maxAge: Long?,
) {

    companion object {

        /**
         * `auth-param` as RFC 9110 §11.2 writes it: a token name, `=`, and either a quoted
         * string or a bare token. The scheme is not matched by this and is therefore skipped
         * rather than deliberately discarded.
         */
        private val PARAMETER = Regex("""([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(?:"([^"]*)"|([^\s,]+))""")

        /**
         * Reads every `WWW-Authenticate` header on the response as one parameter set.
         *
         * First occurrence wins where a name repeats. RFC 9110 allows several challenges in
         * one field and this flattens them, which is the wrong shape for a server offering a
         * genuine choice of schemes — edge offers none, it states one reason for one refusal,
         * and inventing a scheme-selection algorithm for a case that does not arise would be
         * more code to be wrong in.
         */
        fun parse(headers: List<String>): AuthenticateChallenge {
            val parameters = mutableMapOf<String, String>()
            for (header in headers) {
                for (match in PARAMETER.findAll(header)) {
                    val name = match.groupValues[1].lowercase()
                    val value = match.groups[2]?.value ?: match.groupValues[3]
                    parameters.putIfAbsent(name, value)
                }
            }
            return AuthenticateChallenge(
                error = parameters["error"],
                // RFC 9470 §3: space-delimited, in the same syntax the authorization request
                // takes them back in.
                acrValues = parameters["acr_values"]?.split(' ')?.filter { it.isNotBlank() }.orEmpty(),
                // An unparseable `max_age` is dropped rather than failing the step-up: the ACR
                // is the part the re-authorization cannot proceed without, and refusing the
                // whole challenge over the optional half would leave the app with no way
                // forward at all.
                maxAge = parameters["max_age"]?.toLongOrNull(),
            )
        }
    }
}
