import SwiftUI

struct ContentView: View {
    let model: HostModel

    var body: some View {
        VStack(spacing: 8) {
            Button("Sign in") { Task { await model.login(ephemeral: false) } }
                .accessibilityIdentifier("login")
            Button("Sign in (ephemeral)") { Task { await model.login(ephemeral: true) } }
                .accessibilityIdentifier("loginEphemeral")
            Button("Access token") { Task { await model.token() } }
                .accessibilityIdentifier("token")
            Button("Refresh") { Task { await model.refresh() } }
                .accessibilityIdentifier("refresh")
            Button("Sign out") { Task { await model.logout() } }
                .accessibilityIdentifier("logout")
            ScrollView {
                Text(model.log)
                    .font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("status")
            }
        }
        .buttonStyle(.bordered)
        .padding()
    }
}
