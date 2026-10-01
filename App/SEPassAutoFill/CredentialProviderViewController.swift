import AuthenticationServices
import UIKit
import LocalAuthentication
import SEPassCore

/// Read-only, offline provider. Never shares a decrypted cache or silently unlocks.
final class CredentialProviderViewController: ASCredentialProviderViewController,
    UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate {
    private let store = AutoFillStore()
    private var snapshot: AutoFillSnapshot?
    private var entries: [AutoFillEncryptedEntry] = []
    private var requestedDomains: Set<String> = []
    private var busy = false
    private let table = UITableView(frame: .zero, style: .insetGrouped)
    private let search = UISearchBar()
    private let message = UILabel()
    private var requestID = UUID()
    private var authenticationContext: LAContext?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        search.placeholder = "Search password paths"
        search.delegate = self
        message.numberOfLines = 0; message.font = .preferredFont(forTextStyle: .footnote)
        message.textAlignment = .center
        table.dataSource = self; table.delegate = self
        let cancel = UIButton(type: .system)
        cancel.setTitle("Cancel", for: .normal)
        cancel.addTarget(self, action: #selector(cancelRequest), for: .touchUpInside)
        let stack = UIStackView(arrangedSubviews: [cancel, message, search, table])
        stack.axis = .vertical; stack.spacing = 8; stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            stack.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12)
        ])
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        loadViewIfNeeded()
        requestedDomains = Set(serviceIdentifiers.compactMap { service in
            let host = service.type == .URL ? URL(string: service.identifier)?.host : service.identifier
            return host.flatMap(AutoFillPath.domain)
        })
        loadSnapshot()
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        // UI and biometric prompts are forbidden in this callback.
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue))
    }

    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        loadViewIfNeeded()
        let service = credentialIdentity.serviceIdentifier
        let host = service.type == .URL ? URL(string: service.identifier)?.host : service.identifier
        requestedDomains = Set(host.flatMap(AutoFillPath.domain).map { [$0] } ?? [])
        loadSnapshot()
        guard let snapshot, let id = credentialIdentity.recordIdentifier,
              let entry = try? snapshot.entry(for: id) else {
            message.text = "This suggestion is out of date. Open SE Pass to refresh AutoFill."
            entries = []; table.reloadData(); return
        }
        // A visible tap avoids presenting LocalAuthentication before the extension is on-screen.
        entries = [entry]; table.reloadData()
        message.text = "Select the entry to authorize filling with Face ID or Touch ID."
    }

    @available(iOS 17.0, *)
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue))
    }

    @available(iOS 17.0, *)
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        guard let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity else {
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                code: ASExtensionError.credentialIdentityNotFound.rawValue))
            return
        }
        prepareInterfaceToProvideCredential(for: identity)
    }

    override func prepareInterfaceForExtensionConfiguration() {
        loadViewIfNeeded()
        loadSnapshot()
        store.replaceSuggestions(snapshot) { _ in }
        message.text = "Enable AutoFill in the SE Pass app after syncing. Then select SE Pass in iOS AutoFill settings."
        let done = UIButton(type: .system)
        done.setTitle("Done", for: .normal)
        done.addTarget(self, action: #selector(finishConfiguration), for: .touchUpInside)
        table.tableHeaderView = done
        done.frame.size.height = 44
    }

    @objc private func finishConfiguration() { extensionContext.completeExtensionConfigurationRequest() }
    @objc private func cancelRequest() {
        requestID = UUID()
        authenticationContext?.invalidate()
        authenticationContext = nil
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
            code: ASExtensionError.userCanceled.rawValue))
    }

    private func loadSnapshot() {
        do {
            snapshot = try store.load()
            filter(search.text ?? "")
            message.text = requestedDomains.isEmpty ? "Choose a password to fill." : "Requested site: " + requestedDomains.sorted().joined(separator: ", ")
            if entries.isEmpty { message.text = "No passwords available. Sync and enable AutoFill in SE Pass." }
        } catch {
            snapshot = nil; entries = []; table.reloadData()
            message.text = "AutoFill is not ready. Unlock your device, then sync and enable AutoFill in SE Pass."
        }
    }

    private func filter(_ text: String) {
        entries = (snapshot?.entries ?? []).filter { text.isEmpty || $0.id.localizedCaseInsensitiveContains(text) }
        entries.sort {
            let a = !requestedDomains.isDisjoint(with: $0.domains)
            let b = !requestedDomains.isDisjoint(with: $1.domains)
            return a == b ? $0.id < $1.id : a
        }
        table.reloadData()
    }

    func searchBar(_ searchBar: UISearchBar, textDidChange searchText: String) { filter(searchText) }
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { entries.count }
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        let entry = entries[indexPath.row]
        cell.textLabel?.text = entry.label; cell.detailTextLabel?.text = entry.id
        cell.accessoryType = .disclosureIndicator
        return cell
    }
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard !busy else { return }
        let entry = entries[indexPath.row]
        if !requestedDomains.isEmpty && requestedDomains.isDisjoint(with: entry.domains) {
            let alert = UIAlertController(title: "Use a password for another site?",
                message: "\(entry.id) does not match \(requestedDomains.sorted().joined(separator: ", ")).", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
            alert.addAction(UIAlertAction(title: "Use This Entry", style: .default) { [weak self] _ in self?.fill(entry) })
            present(alert, animated: true)
        } else { fill(entry) }
    }

    private func fill(_ entry: AutoFillEncryptedEntry) {
        guard let displayed = snapshot, !busy else { return }
        let request = UUID(); requestID = request
        let context = LAContext(); authenticationContext = context
        busy = true; table.isUserInteractionEnabled = false; search.isUserInteractionEnabled = false
        message.text = "Authorize access to the selected password…"
        // No network, persistent plaintext, logging, or pasteboard use in this process.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            do {
                let current = try self.store.load()
                let selected = try current.entry(for: displayed.identifier(for: entry))
                let info = try JSONDecoder().decode(StoredKeyInfo.self, from: current.keyInfo)
                let decryptor = try DeviceDecryptor.make(info: info, blob: self.store.agreementBlob(for: info),
                    reason: "Fill \(selected.label)", context: context)
                let plaintext = try decryptor.decrypt(selected.ciphertext)
                let login = try AutoFillLogin(plaintext: plaintext, fallbackUsername: selected.label)
                // Revocation or refresh during the biometric prompt must invalidate this request.
                let latest = try self.store.load()
                _ = try latest.entry(for: current.identifier(for: selected))
                DispatchQueue.main.async {
                    guard self.requestID == request else { return }
                    context.invalidate(); self.authenticationContext = nil
                    self.extensionContext.completeRequest(withSelectedCredential:
                        ASPasswordCredential(user: login.username, password: login.password), completionHandler: nil)
                }
            } catch {
                DispatchQueue.main.async {
                    guard self.requestID == request else { return }
                    context.invalidate(); self.authenticationContext = nil
                    self.busy = false; self.table.isUserInteractionEnabled = true; self.search.isUserInteractionEnabled = true
                    self.message.text = "Could not unlock this entry. Authentication may have been cancelled, the key may be unavailable, or the store may have changed. Try again or open SE Pass."
                }
            }
        }
    }
}
