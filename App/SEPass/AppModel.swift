import Foundation
import SwiftUI
import SEPassCore

/// App-wide state: the device key, the synced store location, the remote config, and
/// the loaded password tree. Views observe this.
@MainActor
final class AppModel: ObservableObject {
    @Published var keyInfo: StoredKeyInfo?
    @Published var keyError: String?          // Key-tab feedback; never shown on Sync
    @Published var nodes: [PassNode] = []
    @Published var remote: GitRemote
    @Published var status: String?
    @Published var statusIsError = false
    @Published var isBusy = false
    @Published private(set) var autoFillEnabled = UserDefaults.standard.bool(forKey: "autofill.enabled")
    @Published private(set) var autoFillStatus: String?
    private let autoFill = AutoFillStore()
    private var autoFillRevision = UUID()

    func setAutoFillEnabled(_ enabled: Bool) {
        autoFillEnabled = enabled
        UserDefaults.standard.set(enabled, forKey: "autofill.enabled")
        refreshAutoFill()
    }

    func refreshAutoFill() {
        let revision = UUID(); autoFillRevision = revision
        do {
            let snapshot: AutoFillSnapshot?
            if autoFillEnabled, let info = keyInfo, hasStore {
                snapshot = try autoFill.publish(root: storeURL, info: info,
                                               agreementBlob: keyManager.autoFillAgreementBlob())
                autoFillStatus = "Ready: \(snapshot!.entries.count) encrypted entries."
            } else {
                try autoFill.clear()
                snapshot = nil
                autoFillStatus = autoFillEnabled ? "Generate a key and sync a store first." : "AutoFill is off."
            }
            autoFill.replaceSuggestions(snapshot) { [weak self] error in
                Task { @MainActor in
                    guard let self, self.autoFillRevision == revision else { return }
                    if error != nil { self.autoFillStatus = "The system suggestions could not be updated. Open SE Pass and try Refresh again." }
                }
            }
        } catch {
            // Fail closed: never retain an older usable store after a failed refresh.
            let cleanupError: Error?
            do { try autoFill.clear(); cleanupError = nil } catch { cleanupError = error }
            autoFill.replaceSuggestions(nil) { _ in }
            autoFillStatus = cleanupError == nil
                ? "AutoFill is unavailable: \(error.localizedDescription)"
                : "AutoFill cleanup failed. Turn off SE Pass in iOS AutoFill settings before continuing."
        }
    }

    let keyManager = KeyManager()
    let sshKeys = SSHKeyManager()
    let knownHosts = KnownHostsStore()
    private let git: GitService

    /// Whether a store has been cloned/imported (drives the Sync button label).
    var hasStore: Bool { !nodes.isEmpty }

    /// Cloned working tree lives in Application Support/store.
    let storeURL: URL = {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appendingPathComponent("store", isDirectory: true)
    }()

    private let remoteDefaultsKey = "git.remote"
    private let headDefaultsKey = "git.head"

    /// Commit id of the last successful sync, used to skip re-downloading the store when
    /// the remote hasn't moved. Nil until the first clone (or after the store is erased).
    private var lastSyncedHead: String? {
        get { UserDefaults.standard.string(forKey: headDefaultsKey) }
        set {
            if let newValue { UserDefaults.standard.set(newValue, forKey: headDefaultsKey) }
            else { UserDefaults.standard.removeObject(forKey: headDefaultsKey) }
        }
    }

    init() {
        // Build the git service, teaching it to make an SSH transport from the
        // Secure-Enclave SSH key (with trust-on-first-use host-key pinning) when an
        // ssh:// or git@host:path URL is used.
        let ssh = sshKeys
        let hosts = knownHosts
        let policy = SSHHostKeyPolicy(
            knownLine: { hosts.line(for: $0) },
            onPin: { host, line in hosts.record(host: host, line: line) })
        var service = PureGitService()
        service.sshTransportFactory = { host, port, user, path in
            try ssh.makeTransport(host: host, port: port, username: user, repoPath: path, hostKeyPolicy: policy)
        }
        git = service

        if let data = UserDefaults.standard.data(forKey: remoteDefaultsKey),
           let saved = try? JSONDecoder().decode(GitRemote.self, from: data) {
            remote = saved
        } else {
            remote = GitRemote(url: "")
        }
        keyInfo = keyManager.storedInfo

        #if DEBUG
        if ScreenshotFixture.isActive {
            switch ScreenshotFixture.screen {
            case "key-empty":
                // First-run Key tab: no GPG key generated yet.
                try? FileManager.default.removeItem(at: storeURL)
                keyManager.deleteKey()
                keyInfo = nil
            case "ssh-empty":
                // First-run Sync tab, SSH selected, no SSH key and nothing cloned yet.
                try? FileManager.default.removeItem(at: storeURL)
                sshKeys.deleteKey()
                remote = GitRemote(url: ScreenshotFixture.sampleSSHURL,
                                   authMode: ScreenshotFixture.sshAuthMode)
            default:
                // Populated states: sample store + a generated key.
                ScreenshotFixture.seed(into: storeURL)
                if remote.url.isEmpty { remote = GitRemote(url: ScreenshotFixture.sampleURL) }
                if keyInfo == nil { generateKey(userID: ScreenshotFixture.userID) }
            }
        }
        #endif

        reloadTree()

        #if DEBUG
        if ScreenshotFixture.isActive, ScreenshotFixture.screen == "sync" {
            let count = PassStore.allEntries(nodes).count
            status = "Cloned \(count) password\(count == 1 ? "" : "s")."
        }
        #endif
    }

    // MARK: - SSH key

    func generateSSHKey() {
        run {
            _ = try self.sshKeys.generate()
            self.status = "SSH key generated. Add it as a deploy key."
            self.objectWillChange.send()
        }
    }

    // MARK: - Known SSH hosts (pinned host keys)

    func knownHostList() -> [(host: String, fingerprint: String)] {
        knownHosts.all().map { (host: $0.host, fingerprint: OpenSSHKey.sha256Fingerprint(ofOpenSSHLine: $0.line) ?? "?") }
    }

    func removeKnownHost(_ host: String) {
        knownHosts.remove(host: host)
        objectWillChange.send()
    }

    // MARK: - Key

    func generateKey(userID: String) {
        setAutoFillEnabled(false)
        do {
            // Creation time is "now" truncated to seconds; stable thereafter via cache.
            let now = UInt32(Date().timeIntervalSince1970)
            keyInfo = try keyManager.generate(userID: userID, creationTime: now)
            keyError = nil
            refreshAutoFill()
        } catch {
            keyError = error.localizedDescription
        }
    }

    func deleteKey() {
        setAutoFillEnabled(false)
        keyManager.deleteKey()
        keyInfo = nil
        keyError = nil
    }

    /// Delete only the cloned password store, leaving the Enclave keys, known hosts, and
    /// sync settings intact (so you can re-clone immediately).
    func erasePasswords() {
        setAutoFillEnabled(false)
        try? FileManager.default.removeItem(at: storeURL)
        lastSyncedHead = nil
        nodes = []
    }

    /// Wipe everything — Enclave keys (GPG + SSH), the cloned store, and saved settings —
    /// resetting SE Pass to its first-launch state. Used for testing and as a hard reset.
    func eraseAll() {
        setAutoFillEnabled(false)
        keyManager.deleteKey()
        sshKeys.deleteKey()
        knownHosts.removeAll()
        try? FileManager.default.removeItem(at: storeURL)
        UserDefaults.standard.removeObject(forKey: remoteDefaultsKey)
        lastSyncedHead = nil
        keyInfo = nil
        keyError = nil
        nodes = []
        remote = GitRemote(url: "")
        status = nil          // clear any stale sync status too
        statusIsError = false
    }

    // MARK: - Sync

    func saveRemote(_ newRemote: GitRemote) {
        // Pointing at a different repo/branch invalidates the remembered tip, so the
        // next sync does a full clone rather than trusting a SHA from the old remote.
        if newRemote.url != remote.url || newRemote.branch != remote.branch {
            setAutoFillEnabled(false)
            lastSyncedHead = nil
        }
        remote = newRemote
        if let data = try? JSONEncoder().encode(newRemote) {
            UserDefaults.standard.set(data, forKey: remoteDefaultsKey)
        }
    }

    func clone() {
        runAsync {
            // On refresh, peek at the remote tip first (a cheap ref advertisement, no
            // packfile) and skip the whole download when nothing has changed since the
            // last sync — the common case.
            if self.hasStore, let lastHead = self.lastSyncedHead,
               let remoteHead = try? await self.git.remoteHead(self.remote), remoteHead == lastHead {
                await MainActor.run { self.status = "Already up to date."; self.refreshAutoFill() }
                return
            }
            // Clone into a temp dir and only swap it in on success, so a failed clone
            // (e.g. wrong/missing credentials) never destroys the existing store.
            let temp = self.storeURL.deletingLastPathComponent().appendingPathComponent(".store-clone")
            try? FileManager.default.removeItem(at: temp)
            try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
            let head = try await self.git.clone(self.remote, into: temp)
            await MainActor.run {
                try? FileManager.default.removeItem(at: self.storeURL)
                try? FileManager.default.moveItem(at: temp, to: self.storeURL)
                self.lastSyncedHead = head
                self.reloadTree()
                let count = PassStore.allEntries(self.nodes).count
                self.status = "Cloned \(count) password\(count == 1 ? "" : "s")."
            }
        }
    }

    /// Import an already-cloned store from a local folder (e.g. picked via Files). Works
    /// today without the git transport and is handy for `file://`/local repos.
    func importLocalStore(from url: URL) {
        run {
            self.setAutoFillEnabled(false)
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            try? FileManager.default.removeItem(at: self.storeURL)
            try FileManager.default.copyItem(at: url, to: self.storeURL)
            self.lastSyncedHead = nil   // imported tree has no known remote commit
            self.reloadTree()
            self.status = "Imported \(self.nodes.count) top-level items."
        }
    }

    func reloadTree() {
        defer { refreshAutoFill() }
        guard FileManager.default.fileExists(atPath: storeURL.path) else { nodes = []; return }
        nodes = PassStore(root: storeURL).load()
    }

    // MARK: - Decrypt

    func decrypt(_ node: PassNode) async throws -> String {
        #if DEBUG
        if ScreenshotFixture.isActive { return ScreenshotFixture.plaintext(for: node) }
        #endif
        let decryptor = try keyManager.makeDecryptor(reason: "Decrypt \(node.name)")
        let ciphertext = try Data(contentsOf: node.url)
        let plaintext = try decryptor.decrypt(ciphertext)
        return String(data: plaintext, encoding: .utf8) ?? "<binary data>"
    }

    // MARK: - Helpers

    private func run(_ work: @escaping () throws -> Void) {
        isBusy = true; status = nil; statusIsError = false
        do { try work() } catch { status = error.localizedDescription; statusIsError = true }
        isBusy = false
    }

    private func runAsync(_ work: @escaping () async throws -> Void) {
        isBusy = true; status = nil; statusIsError = false
        Task {
            do { try await work() }
            catch { await MainActor.run { self.status = error.localizedDescription; self.statusIsError = true } }
            await MainActor.run { self.isBusy = false }
        }
    }
}
