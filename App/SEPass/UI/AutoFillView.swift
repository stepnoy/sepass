import SwiftUI
import AuthenticationServices

struct AutoFillView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var systemEnabled = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("Share passwords with AutoFill", isOn: Binding(
                        get: { model.autoFillEnabled }, set: { model.setAutoFillEnabled($0) }))
                    if let status = model.autoFillStatus { Text(status).font(.footnote) }
                    Button("Refresh AutoFill") { model.refreshAutoFill(); checkSystem() }
                } footer: {
                    Text("Shares an encrypted copy with the SE Pass extension on this device. Face ID or Touch ID authorizes each fill. Git credentials are kept in the main app.")
                }
                Section("iOS settings") {
                    Label(systemEnabled ? "SE Pass is enabled in iOS" : "Select SE Pass in iOS AutoFill settings",
                          systemImage: systemEnabled ? "checkmark.circle" : "gear")
                    Text("In Settings, search for AutoFill and enable SE Pass as a password provider. On older iOS versions, open Passwords → Password Options.")
                    Text("After enabling it, return here and tap Refresh AutoFill to update keyboard suggestions.")
                }
                Section("Password format") {
                    Text("The first line is the password. Add login: or username: on a following line; otherwise the entry name is used as the login.")
                    Text("Use paths such as example.com/alice for site suggestions. Other entries are available through search. Paths and entry names are visible to the system; password contents are not indexed.")
                }
            }
            .navigationTitle("AutoFill")
            .onAppear { checkSystem() }
            .onChange(of: scenePhase) { phase in
                if phase == .active { checkSystem(); model.refreshAutoFill() }
            }
        }
    }

    private func checkSystem() {
        ASCredentialIdentityStore.shared.getState { state in
            DispatchQueue.main.async { systemEnabled = state.isEnabled }
        }
    }
}
