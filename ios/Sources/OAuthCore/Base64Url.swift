import Foundation

/// base64url without padding: RFC 7636 appendix A for PKCE, RFC 7515 section 2 for JOSE.
///
/// Foundation's `Data(base64Encoded:)` speaks only the standard alphabet, and is lenient in
/// ways that matter for a security parser, so the alphabet is checked here first and the two
/// URL-safe characters are mapped over to the standard ones afterwards.
enum Base64Url {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// The decoded bytes, or nil when `s` is not base64url. Trailing padding is tolerated
    /// (some providers pad), but the standard alphabet's `+` and `/` are not: a token that
    /// contains them was not produced by a JOSE implementation.
    static func decode(_ s: String) -> Data? {
        var body = Substring(s)
        while body.hasSuffix("=") { body = body.dropLast() }
        // Padding in the middle of the text is not padding; it falls out at the alphabet check.
        guard body.utf8.allSatisfy(Self.isAlphabet) else { return nil }
        // Four characters carry three bytes; a remainder of one carries none and cannot occur.
        guard body.utf8.count % 4 != 1 else { return nil }
        var standard = String(body)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.utf8.count % 4) % 4)
        return Data(base64Encoded: standard)
    }

    private static func isAlphabet(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"):
            return true
        default:
            return false
        }
    }
}
