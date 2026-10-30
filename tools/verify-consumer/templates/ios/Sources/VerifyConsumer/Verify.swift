import OAuthClient

// Never run: the build is the test. The module is OAuthClient (the product is VersolaOAuth), and
// the facade's configuration and client are what an app names first.

public func verifyConfiguration() throws -> OAuthConfiguration {
    try OAuthConfiguration(
        issuer: "https://id.example.com",
        clientId: "verify-consumer",
        redirectUri: "https://app.example.com/oauth"
    )
}

public func verifyClientType() -> OAuthClient.Type {
    OAuthClient.self
}
