import Foundation
import AuthenticationServices
import Security
import SEPassCore

/// Separate capability from the app's private Keychain: no Git or signing credentials.
struct AutoFillStore {
    private let service = "com.sepass.autofill.agreement"

    private var group: String? { Bundle.main.object(forInfoDictionaryKey: "AutoFillAppGroup") as? String }
    private var keychainGroup: String? { Bundle.main.object(forInfoDictionaryKey: "AutoFillKeychainGroup") as? String }

    private func snapshotURL() throws -> URL {
        guard let group, !group.contains("$("),
              var root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            throw StoreError.configuration
        }
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        try root.setResourceValues(values)
        return root.appendingPathComponent("autofill-v1.json")
    }

    private func query(account: String? = nil) throws -> [String: Any] {
        guard let keychainGroup, !keychainGroup.contains("$(") else { throw StoreError.configuration }
        var result: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccessGroup as String: keychainGroup
        ]
        if let account { result[kSecAttrAccount as String] = account }
        return result
    }

    func load() throws -> AutoFillSnapshot {
        let url = try snapshotURL()
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        guard size <= AutoFillSnapshot.maxEncodedBytes else { throw AutoFillDataError.tooLarge }
        let data = try Data(contentsOf: url)
        guard data.count <= AutoFillSnapshot.maxEncodedBytes else { throw AutoFillDataError.tooLarge }
        let snapshot = try JSONDecoder().decode(AutoFillSnapshot.self, from: data)
        try snapshot.validate()
        return snapshot
    }

    func agreementBlob(for info: StoredKeyInfo) throws -> Data {
        var q = try query(account: info.subkeyFingerprintHex)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { throw StoreError.keyUnavailable }
        return data
    }

    /// Called only by the containing app, never from an extension request.
    func publish(root: URL, info: StoredKeyInfo, agreementBlob: Data) throws -> AutoFillSnapshot {
        let snapshot = try AutoFillSnapshot(keyInfo: JSONEncoder().encode(info), entries: AutoFillSnapshot.scan(root: root))
        let encoded = try JSONEncoder().encode(snapshot)
        guard encoded.count <= AutoFillSnapshot.maxEncodedBytes else { throw AutoFillDataError.tooLarge }
        let q = try query(account: info.subkeyFingerprintHex)
        let attributes: [String: Any] = [
            kSecValueData as String: agreementBlob,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        var status = SecItemUpdate(q as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(q.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw StoreError.keyUnavailable }
        try encoded.write(to: snapshotURL(), options: [.atomic, .completeFileProtection])
        return snapshot
    }

    func clear() throws {
        // Try both revocation steps even if one fails (e.g. file protection at lock).
        var failure: Error?
        do {
            let url = try snapshotURL()
            if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
        } catch { failure = error }
        do {
            let status = SecItemDelete(try query() as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw StoreError.keyUnavailable }
        } catch { failure = error }
        if let failure { throw failure }
    }

    func replaceSuggestions(_ snapshot: AutoFillSnapshot?, completion: @escaping (Error?) -> Void) {
        let identities: [ASPasswordCredentialIdentity] = snapshot?.entries.flatMap { entry in
            entry.domains.map { domain in
                ASPasswordCredentialIdentity(serviceIdentifier: .init(identifier: domain, type: .domain),
                    user: entry.label, recordIdentifier: snapshot!.identifier(for: entry))
            }
        } ?? []
        ASCredentialIdentityStore.shared.getState { state in
            guard state.isEnabled else { completion(nil); return }
            ASCredentialIdentityStore.shared.replaceCredentialIdentities(with: identities) { _, error in
                completion(error)
            }
        }
    }

    enum StoreError: LocalizedError {
        case configuration, keyUnavailable
        var errorDescription: String? {
            switch self {
            case .configuration: return "AutoFill sharing is unavailable. Check the app's signing and App Group configuration."
            case .keyUnavailable: return "The AutoFill decryption key is unavailable. Open SE Pass and enable AutoFill again."
            }
        }
    }
}
