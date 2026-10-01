import Foundation
import XCTest
@testable import SEPassCore

/// Decrypts committed fixtures with no external dependencies, so the core decryption
/// path is covered even where gpg/rpgp aren't installed (e.g. CI). Two fixtures share
/// one recipient key (scalar 0x42…42) and plaintext:
///   • `message.gpg`          — binary, produced by gpg  (the `pass` backend)
///   • `message-armored.asc`  — ASCII-armored, produced by rpgp (the `prs` backend)
/// so both real-world backend/format combinations are exercised on every run.
final class HermeticDecryptTests: XCTestCase {

    func testDecryptBinaryFixture() throws { try decryptFixture(named: "message.gpg") }

    /// Regression for the `prs`/rpgp armored-store case that produced
    /// "malformed (packet header high bit not set)" before de-armoring was added.
    func testDecryptArmoredFixture() throws { try decryptFixture(named: "message-armored.asc") }

    private func decryptFixture(named file: String) throws {
        guard let dir = Bundle.module.url(forResource: "decrypt", withExtension: nil,
                                          subdirectory: "Fixtures") else {
            throw XCTSkip("fixture not generated (run with SEPASS_REGEN=1)")
        }
        let ciphertext = try Data(contentsOf: dir.appendingPathComponent(file))
        let metaData = try Data(contentsOf: dir.appendingPathComponent("meta.json"))
        let meta = try JSONSerialization.jsonObject(with: metaData) as! [String: Any]

        let scalar = bytes(fromHex: meta["scalarHex"] as! String)
        let agreement = try SoftwareP256KeyAgreement(rawRepresentation: Data(scalar))
        let recipient = RecipientKey(
            fingerprint: bytes(fromHex: meta["subkeyFingerprintHex"] as! String),
            keyID: bytes(fromHex: meta["subkeyKeyIDHex"] as! String),
            kdfHash: HashAlgorithm(rawValue: UInt8(meta["kdfHash"] as! Int))!,
            kdfSymmetric: SymmetricAlgorithm(rawValue: UInt8(meta["kdfSymmetric"] as! Int))!)

        let plaintext = try PGPDecryptor(agreement: agreement, recipient: recipient).decrypt(ciphertext)
        XCTAssertEqual(String(data: plaintext, encoding: .utf8), meta["plaintext"] as? String,
                       "\(file) did not decrypt to the expected plaintext")

        // Exercise the actual AutoFill snapshot -> identity -> decrypt -> login path
        // for both pass binary and prs armored stores, using only public fixtures.
        let entry = AutoFillEncryptedEntry(id: "example.com/alice", ciphertext: ciphertext)
        let published = try AutoFillSnapshot(keyInfo: metaData, entries: [entry])
        let loaded = try JSONDecoder().decode(AutoFillSnapshot.self, from: JSONEncoder().encode(published))
        try loaded.validate()
        let selected = try loaded.entry(for: published.identifier(for: entry))
        let login = try AutoFillLogin(
            plaintext: PGPDecryptor(agreement: agreement, recipient: recipient).decrypt(selected.ciphertext),
            fallbackUsername: selected.label)
        XCTAssertEqual(login.username, "alice")
        XCTAssertEqual(login.password, "fixture-secret-🔐")
    }

    private func bytes(fromHex hex: String) -> [UInt8] {
        var result = [UInt8](); var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            result.append(UInt8(hex[idx..<next], radix: 16)!)
            idx = next
        }
        return result
    }
}
