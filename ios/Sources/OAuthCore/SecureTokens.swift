import Foundation

/// `state` and `nonce`, and the comparison a redirect is validated with.
enum SecureTokens {
    /// `bytes` of CSPRNG output as base64url, 43 characters for the default 32 bytes. Well above
    /// the 128-bit floor of the spec, and short enough for a `state` to survive providers that
    /// cap its length. The floor is enforced here rather than trusted to the caller: a request
    /// for fewer than 16 bytes still yields 16.
    static func generate(_ random: RandomSource, bytes: Int = 32) -> String {
        Base64Url.encode(Data(random.bytes(max(bytes, 16))))
    }

    /// Constant-time comparison of the UTF-8 bytes. Written out rather than delegated to
    /// `==`, which returns at the first differing byte and so leaks the length of the matching
    /// prefix to anything that can time it. The length difference is folded into the
    /// accumulator instead of short-circuiting, and the loop runs over all of `a` whatever
    /// the lengths are.
    static func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        let left = Array(a.utf8)
        let right = Array(b.utf8)
        // Index `right` modulo its length so an empty right-hand side does not trap: the
        // mismatch is already recorded in `difference` and cannot be cancelled out.
        let probe = right.isEmpty ? [0] : right
        var difference = UInt32(truncatingIfNeeded: left.count ^ right.count)
        for index in left.indices {
            difference |= UInt32(left[index] ^ probe[index % probe.count])
        }
        return difference == 0
    }
}
