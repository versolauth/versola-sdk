import Foundation

/// The offset between this device's clock and the server's, learned from the `Date` header.
///
/// Device clocks are wrong far more often than anyone expects, and a server verifies a proof's
/// `iat` within a bounded leeway (RFC 9449 section 4.3), so a phone five minutes fast has every
/// proof refused for a reason that looks nothing like a clock problem from the app's side. The
/// single `invalid_dpop_proof` retry (`spec/state-machine.md`) is only worth sending if its
/// proof is minted from the clock this learned, which is why it is fed from every response and
/// not only from a refusal.
///
/// Mirrors Android's `ClockSkew`. In memory only, re-learned after process death (scenario 06):
/// persisting it would correct today's proofs by an offset measured against a clock the user
/// may have fixed since.
package struct ClockSkew: Sendable {
    /// What an offset may be and still be believed. A device whose clock is further from the
    /// provider's than this cannot complete a TLS handshake against most certificates either, so
    /// a `Date` implying more is a stale cached response or a broken intermediary, and an `iat`
    /// corrected by it would be wrong rather than right. Ignoring it leaves the device clock in
    /// use, which is what happened before anything was learned.
    package static let maxOffset: TimeInterval = 30 * 24 * 3600

    /// Server time minus device time, nil until a response with a usable `Date` has been seen.
    /// One for the client, whichever origin taught it, and the last response wins (Android's
    /// design too): it is a fact about this device's clock, not about a server.
    package private(set) var offset: TimeInterval?

    package init() {}

    /// Learns from one response's `Date`, read at `deviceNow`. An absent, unparseable or
    /// implausible value leaves any previously learned offset in place: it says nothing about the
    /// clock either way, and discarding a working correction would put every proof outside the
    /// server's leeway again. Only the preferred RFC 9110 section 5.6.7 form is read; guessing
    /// about an obsolete date format is worse than not correcting at all.
    ///
    /// A response with an `Age` other than `0` is a cache's, and its `Date` is when the origin
    /// generated it, not now (RFC 9111 section 5.1): learning from it would shift the offset by
    /// the age of the response, which the 30-day bound does nothing to prevent. It is skipped, and
    /// so is an `Age` that cannot be read.
    package mutating func learn(dateHeader: String?, age: String? = nil, deviceNow: Date) {
        if let age, age.trimmingCharacters(in: .whitespaces) != "0" { return }
        guard let dateHeader, let server = HTTPDate.parse(dateHeader) else { return }
        let learned = server.timeIntervalSince(deviceNow)
        guard learned.isFinite, abs(learned) <= Self.maxOffset else { return }
        offset = learned
    }

    /// The device time corrected by whatever has been learned: what every `iat` is stamped from.
    package func corrected(_ deviceNow: Date) -> Date {
        deviceNow.addingTimeInterval(offset ?? 0)
    }
}
