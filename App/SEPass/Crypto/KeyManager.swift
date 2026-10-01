import Foundation
import CryptoKit
import SEPassCore

/// Owns the device keypair lifecycle: generation, persistence, public-key export, and
/// building a biometric-gated decryptor. Hides the Secure-Enclave-vs-software split.
final class KeyManager {
    private let signingAccount = "se-signing-key"
    private let agreementAccount = "se-agreement-key"
    private let infoURL: URL

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        infoURL = support.appendingPathComponent("keyinfo.json")
    }

    var storedInfo: StoredKeyInfo? {
        guard let data = try? Data(contentsOf: infoURL) else { return nil }
        return try? JSONDecoder().decode(StoredKeyInfo.self, from: data)
    }

    var hasKey: Bool { storedInfo != nil }

    /// Generate a fresh keypair, persist it, and return the exported public key. The
    /// creation time is supplied by the caller so the result is reproducible/testable.
    func generate(userID: String, creationTime: UInt32) throws -> StoredKeyInfo {
        let signer: PGPSigner
        let agreement: PGPKeyAgreement

        #if targetEnvironment(simulator)
        // No Secure Enclave in the simulator: use software keys so the app runs. The
        // signing key is only needed during this call (the public key is cached
        // afterwards), so only the agreement key is persisted.
        let swSign = SoftwareP256Signer()
        let swAgree = SoftwareP256KeyAgreement()
        try Keychain.set(swAgree.rawRepresentation, account: agreementAccount)
        signer = swSign; agreement = swAgree
        #else
        let seSign = try SecureEnclaveFactory.makeSigningKey()
        let seAgree = try SecureEnclaveFactory.makeAgreementKey()
        try Keychain.set(seSign.dataRepresentation, account: signingAccount)
        try Keychain.set(seAgree.dataRepresentation, account: agreementAccount)
        signer = SecureEnclaveSigner(key: seSign)
        agreement = SecureEnclaveKeyAgreement(key: seAgree)
        #endif

        let material = try OpenPGPKeyExporter.export(
            signer: signer, agreement: agreement, userID: userID, creationTime: creationTime)
        let info = StoredKeyInfo(
            armoredPublicKey: material.armoredPublicKey,
            primaryFingerprintHex: material.primaryFingerprint.map { String(format: "%02x", $0) }.joined(),
            subkeyFingerprintHex: material.recipient.fingerprint.map { String(format: "%02x", $0) }.joined(),
            subkeyKeyIDHex: material.recipient.keyID.map { String(format: "%02x", $0) }.joined(),
            kdfHash: material.recipient.kdfHash.rawValue,
            kdfSymmetric: material.recipient.kdfSymmetric.rawValue,
            creationTime: creationTime, userID: userID)
        try JSONEncoder().encode(info).write(to: infoURL, options: .completeFileProtection)
        return info
    }

    func deleteKey() {
        Keychain.delete(account: signingAccount)
        Keychain.delete(account: agreementAccount)
        try? FileManager.default.removeItem(at: infoURL)
    }

    /// Build a decryptor backed by the agreement key. On device this loads the Enclave
    /// key with an LAContext so the ECDH step prompts for biometrics.
    func makeDecryptor(reason: String) throws -> PGPDecryptor {
        guard let info = storedInfo, let blob = Keychain.get(account: agreementAccount) else {
            throw KeyError.noKey
        }
        return try DeviceDecryptor.make(info: info, blob: blob, reason: reason)
    }

    /// Share only the Enclave-wrapped agreement key, never signing/SSH/Git secrets.
    func autoFillAgreementBlob() throws -> Data {
        guard let blob = Keychain.get(account: agreementAccount) else { throw KeyError.noKey }
        return blob
    }

    enum KeyError: Error, LocalizedError {
        case noKey
        var errorDescription: String? {
            switch self {
            case .noKey:
                return """
                This device has no decryption key yet. Go to the Key tab and generate one, \
                then re-initialize your pass repo to include its public key and sync again.
                """
            }
        }
    }
}
