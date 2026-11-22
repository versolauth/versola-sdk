import Foundation

/// The scope of the stored grant, so that a step-up can ask for it again without the app having to
/// remember what it passed to `login()` in another process (`spec/versola-sdk-api.md` section 6 and
/// 11). Not credential material: scope names. A plain file beside the credentials, removed with them.
package protocol GrantedScopeStore: Sendable {
    /// Empty when nothing was saved or the copy cannot be read: a step-up then asks for `openid` and
    /// `offline_access` alone, and the session is unaffected.
    func load() async -> Set<String>
    func save(_ scopes: Set<String>) async
    func clear() async
}

package actor InMemoryGrantedScopeStore: GrantedScopeStore {
    private var scopes: Set<String>

    package init(_ scopes: Set<String> = []) { self.scopes = scopes }

    package func load() -> Set<String> { scopes }
    package func save(_ scopes: Set<String>) { self.scopes = scopes }
    package func clear() { scopes = [] }
}

package struct FileGrantedScopeStore: GrantedScopeStore {
    private let file: URL

    package init(file: URL) { self.file = file }

    package func load() async -> Set<String> {
        guard let data = try? Data(contentsOf: file), let text = String(data: data, encoding: .utf8) else { return [] }
        return Set(text.split(separator: " ").map(String.init))
    }

    /// Not fatal: a lost copy costs a step-up its remembered scopes, not a session.
    package func save(_ scopes: Set<String>) async {
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Data(scopes.sorted().joined(separator: " ").utf8).write(to: file, options: .atomic)
    }

    package func clear() async {
        try? FileManager.default.removeItem(at: file)
    }
}
