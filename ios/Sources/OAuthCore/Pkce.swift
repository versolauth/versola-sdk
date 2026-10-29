import CryptoKit
import Foundation

/// RFC 7636 PKCE. S256 always: there is deliberately no way to express `plain` or "no PKCE"
/// here, because a provider that offers only those is one this SDK refuses to talk to.
package struct CodeVerifier: Sendable, Equatable, CustomStringConvertible {
    /// The secret itself. Read only to persist it with the pending request and to redeem the
    /// code; `description` never shows it.
    package let value: String

    private init(trusted value: String) { self.value = value }

    /// A verifier restored from storage or handed over from a pending request. Validated
    /// against RFC 7636 section 4.1 (43 to 128 characters of the unreserved set), so a corrupt
    /// record fails here rather than at the token endpoint after the code is spent.
    package init(value: String) throws {
        let bytes = value.utf8
        guard (43...128).contains(bytes.count), bytes.allSatisfy(Self.isUnreserved) else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "malformed PKCE code verifier"))
        }
        self.value = value
    }

    /// 32 bytes of CSPRNG output, 43 base64url characters: the shortest verifier RFC 7636
    /// permits, and 256 bits of entropy.
    package static func generate(_ random: RandomSource) -> CodeVerifier {
        CodeVerifier(trusted: SecureTokens.generate(random, bytes: 32))
    }

    /// The `code_challenge`: base64url(SHA-256(ASCII(code_verifier))), RFC 7636 section 4.2.
    package func challengeS256() -> String {
        Base64Url.encode(Data(SHA256.hash(data: Data(value.utf8))))
    }

    /// Credential material: never printed, including through an accidental string interpolation.
    package var description: String { "CodeVerifier(redacted)" }

    private static func isUnreserved(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."),
             UInt8(ascii: "_"), UInt8(ascii: "~"):
            return true
        default:
            return false
        }
    }
}
