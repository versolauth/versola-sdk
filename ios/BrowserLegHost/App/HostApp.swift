import SwiftUI

/// The host app of the browser-leg device tier (`develop.md`, "The browser leg on a simulator"):
/// a small app over the generic facade whose screen is a log of what the SDK did, so that the
/// UI tests in `UITests/` can drive it and the system's sign-in sheet and read the outcome back.
/// It is also the quickest way to try the SDK by hand: point it at a provider and press the
/// buttons. Nothing is published from it.
@main
struct HostApp: App {
    @State private var model = HostModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                // A redirect the system handed to the app (a custom-scheme URL, a Universal
                // Link): the facade says whether it was the one it was waiting for.
                .onOpenURL { url in Task { await model.handle(url) } }
                .task { await model.start() }
        }
    }
}
