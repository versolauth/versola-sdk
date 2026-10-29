package versola.sdk.core

import versola.oauth.core.VersolaError

/**
 * Edge's 404 on a native endpoint: it fronts no such client. The client is not registered as
 * `native` with `tls_client_auth` and an edge certificate, its tenant is not assigned to this
 * edge, or edge has no `native` block — all deployment, none of them the user's. Under
 * [BackChannel.Edge] this is the single most common first-run mistake.
 */
public data class EdgeClientUnknown(public val clientId: String) : VersolaError.Configuration.Detail.Extension()
