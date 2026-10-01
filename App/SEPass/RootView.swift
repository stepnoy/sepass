import SwiftUI

/// The three jobs SE Pass does, one tab each. Order: Passwords, Sync, Key. On launch we
/// land on the tab that matches where the user is in setup.
struct RootView: View {
    @EnvironmentObject var model: AppModel
    @State private var selection: Tab = .passwords
    @State private var didSetInitialTab = false

    enum Tab { case passwords, sync, key, autoFill, about }

    var body: some View {
        TabView(selection: $selection) {
            BrowseView()
                .tabItem { Label("Passwords", systemImage: "lock.fill") }
                .tag(Tab.passwords)
            SyncView()
                .tabItem { Label("Sync", systemImage: "arrow.triangle.2.circlepath") }
                .tag(Tab.sync)
            KeyView()
                .tabItem { Label("Key", systemImage: "key.fill") }
                .tag(Tab.key)
            AutoFillView()
                .tabItem { Label("AutoFill", systemImage: "rectangle.and.pencil.and.ellipsis") }
                .tag(Tab.autoFill)
            AboutView()
                .tabItem { Label("About", systemImage: "info.circle") }
                .tag(Tab.about)
        }
        .onAppear {
            guard !didSetInitialTab else { return }
            didSetInitialTab = true
            selection = initialTab()
        }
    }

    /// Show passwords if a store has been cloned; otherwise guide setup — Key first if no
    /// Enclave GPG key exists yet, else Sync.
    private func initialTab() -> Tab {
        #if DEBUG
        if ScreenshotFixture.isActive {
            switch ScreenshotFixture.screen {
            case "sync", "ssh-empty": return .sync
            case "key", "key-empty": return .key
            default: return .passwords    // "tree" and "entry" both start here
            }
        }
        #endif
        if model.hasStore { return .passwords }
        if model.keyInfo == nil { return .key }
        return .sync
    }
}
