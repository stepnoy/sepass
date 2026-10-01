import Foundation
import CryptoKit
import LocalAuthentication
import SEPassCore

/// Persisted, non-secret description of the generated key, cached so the app can show
/// the public key and decrypt without re-running (or biometric-prompting for) the
/// signing key on every launch.
struct StoredKeyInfo: Codable {
    var armoredPublicKey: String
    var primaryFingerprintHex: String
    var subkeyFingerprintHex: String
    var subkeyKeyIDHex: String
    var kdfHash: UInt8
    var kdfSymmetric: UInt8
    var creationTime: UInt32
    var userID: String

    var recipient: RecipientKey {
        RecipientKey(fingerprint: Hex.bytes(subkeyFingerprintHex),
                     keyID: Hex.bytes(subkeyKeyIDHex),
                     kdfHash: HashAlgorithm(rawValue: kdfHash) ?? .sha256,
                     kdfSymmetric: SymmetricAlgorithm(rawValue: kdfSymmetric) ?? .aes256)
    }
}

enum Hex {
    static func bytes(_ s: String) -> [UInt8] {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let j = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            if let b = UInt8(s[i..<j], radix: 16) { out.append(b) }
            i = j
        }
        return out
    }
}

/// Shared crypto construction; no access to app-private Keychain or Git credentials.
enum DeviceDecryptor {
    static func make(info: StoredKeyInfo, blob: Data, reason: String, context: LAContext = LAContext()) throws -> PGPDecryptor {
        let agreement: PGPKeyAgreement
        #if targetEnvironment(simulator)
        agreement = try SoftwareP256KeyAgreement(rawRepresentation: blob)
        #else
        context.localizedReason = reason
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: context)
        agreement = SecureEnclaveKeyAgreement(key: key)
        #endif
        return PGPDecryptor(agreement: agreement, recipient: info.recipient)
    }

}
