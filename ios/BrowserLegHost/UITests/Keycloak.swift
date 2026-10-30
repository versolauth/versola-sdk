import Foundation

/// The provider's side of the story, read from Keycloak's admin API: whether alice has a sign-in
/// session at the provider. "The SDK says it signed out" is the SDK's word; this is the
/// provider's. The admin credentials are the throwaway ones of
/// `conformance/providers/keycloak/docker-compose.yml`.
struct Keycloak {
    let base: String
    let realm: String
    let adminUser: String
    let adminPassword: String

    init(issuer: String, adminUser: String = "admin", adminPassword: String = "admin") {
        let parts = issuer.components(separatedBy: "/realms/")
        base = parts[0]
        realm = parts.count > 1 ? parts[1] : "conformance"
        self.adminUser = adminUser
        self.adminPassword = adminPassword
    }

    func sessions(of username: String) async throws -> Int {
        let token = try await token()
        let id = try await userId(username, token: token)
        let data = try await request("GET", "/admin/realms/\(realm)/users/\(id)/sessions", token: token)
        return (try JSONSerialization.jsonObject(with: data) as? [Any])?.count ?? -1
    }

    /// Ends every session of `username` at the provider, so a test starts from a signed-out browser.
    func endSessions(of username: String) async throws {
        let token = try await token()
        let id = try await userId(username, token: token)
        _ = try await request("POST", "/admin/realms/\(realm)/users/\(id)/logout", token: token)
    }

    private func userId(_ username: String, token: String) async throws -> String {
        let data = try await request("GET", "/admin/realms/\(realm)/users?username=\(username)&exact=true", token: token)
        guard let users = try JSONSerialization.jsonObject(with: data) as? [[String: Any]], users.count == 1,
              let id = users[0]["id"] as? String
        else { throw KeycloakError.unexpected("expected one user named \(username)") }
        return id
    }

    private func token() async throws -> String {
        let form = "grant_type=password&client_id=admin-cli&username=\(adminUser)&password=\(adminPassword)"
        let data = try await request("POST", "/realms/master/protocol/openid-connect/token", form: form)
        guard let token = (try JSONSerialization.jsonObject(with: data) as? [String: Any])?["access_token"] as? String
        else { throw KeycloakError.unexpected("no admin token") }
        return token
    }

    private func request(_ method: String, _ path: String, form: String? = nil, token: String? = nil) async throws -> Data {
        var request = URLRequest(url: URL(string: base + path)!)
        request.httpMethod = method
        request.timeoutInterval = 10
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let form {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            request.httpBody = Data(form.utf8)
        } else if method == "POST" {
            request.httpBody = Data()
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else { throw KeycloakError.unexpected("\(method) \(path) answered \(status)") }
        return data
    }
}

enum KeycloakError: Error {
    case unexpected(String)
}
