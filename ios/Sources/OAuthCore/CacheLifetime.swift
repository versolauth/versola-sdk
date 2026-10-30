import Foundation

/// How long a fetched key set or discovery document is trusted before it is fetched again
/// (`spec/oauth-sdk-api.md` section 4): the provider's own `Cache-Control: max-age` held between
/// bounds the SDK chooses, and a day when the provider says nothing.
///
/// The ceiling is a day however long the provider asks for: a withdrawn signing key or a moved
/// endpoint must not stay trusted for a year because a CDN header said so. The floor stops a
/// `max-age=0` or `no-store` from turning every login into a request for the key set; one refetch
/// on a `kid` the set lacks (a rotation) is not governed by any of this.
package enum CacheLifetime {
    package static let defaultLifetime: TimeInterval = 24 * 3600
    package static let minimum: TimeInterval = 300
    package static let maximum: TimeInterval = 24 * 3600
    /// How long past its lifetime a key set may still be used to judge the ID token of a refresh
    /// when the provider cannot be reached for a new one (`JwksStaleness`). A week: an outage
    /// longer than that is the app's to handle, and a key the provider withdrew is not trusted
    /// past it by any path.
    package static let maximumStale: TimeInterval = 7 * 24 * 3600

    /// The lifetime a response with this `Cache-Control` value earns. Only the directives of a
    /// private cache are read (`max-age`, `no-store`, `no-cache`): `s-maxage` is for shared ones.
    /// A malformed value is as good as none, never an error.
    package static func of(_ cacheControl: String?) -> TimeInterval {
        guard let cacheControl else { return defaultLifetime }
        var maxAge: TimeInterval?
        for directive in cacheControl.split(separator: ",") {
            let parts = directive.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard let name = parts.first?.lowercased() else { continue }
            switch name {
            case "no-store", "no-cache":
                return minimum
            case "max-age":
                guard parts.count == 2 else { continue }
                let value = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                // Digits only: a sign, a fraction or text is malformed, and `Double` would take them.
                guard !value.isEmpty, value.allSatisfy(\.isASCII), value.allSatisfy(\.isNumber), let seconds = Double(value) else { continue }
                maxAge = seconds
            default:
                continue
            }
        }
        guard let maxAge else { return defaultLifetime }
        return min(max(maxAge, minimum), maximum)
    }
}
