import XCTest
@testable import SEPassCore

final class AutoFillTests: XCTestCase {
    func testPassLoginParsingPreservesPasswordAndHandlesCRLF() throws {
        let login = try AutoFillLogin(plaintext: Data(" p:a ss \r\nURL: https://example.com\r\nLOGIN: \r\nUsername: alice\r\nuser: ignored".utf8), fallbackUsername: "fallback")
        XCTAssertEqual(login.password, " p:a ss ")
        XCTAssertEqual(login.username, "alice")
        XCTAssertEqual(try AutoFillLogin(plaintext: Data("secret\nnotes".utf8), fallbackUsername: "account").username, "account")
        for data in [Data(), Data("\nlogin: alice".utf8), Data([0xff]), Data("bad\0text".utf8)] {
            XCTAssertThrowsError(try AutoFillLogin(plaintext: data, fallbackUsername: "x"))
        }
    }

    func testDomainMatchingIsExactAndRejectsURLTricks() {
        XCTAssertEqual(AutoFillPath.domains(in: "work/EXAMPLE.COM/alice"), ["example.com"])
        XCTAssertEqual(AutoFillPath.domain("Example.COM."), "example.com")
        XCTAssertNotEqual(AutoFillPath.domain("example.com.evil.test"), "example.com")
        for domain in ["example.com@evil.test", "https://example.com", "example.com:443", "*.example.com", "a..com", "-x.com", "exаmple.com", "127.0.0.1"] {
            XCTAssertNil(AutoFillPath.domain(domain), domain)
        }
        for path in ["../secret", "/secret", "x//y", "x/.git/y", "x/../y", "x\\y", "x\ny", String(repeating: "a/", count: 129) + "x", String(repeating: "a", count: 4097)] {
            XCTAssertFalse(AutoFillPath.isSafe(path), path)
        }
    }

    func testStaleIdentityCannotSelectReplacementStoreEntry() throws {
        let entry = AutoFillEncryptedEntry(id: "example.com/alice", ciphertext: Data([1]))
        let a = try AutoFillSnapshot(keyInfo: Data(), entries: [entry])
        let b = try AutoFillSnapshot(keyInfo: Data(), entries: [entry])
        XCTAssertEqual(try a.entry(for: a.identifier(for: entry)).id, entry.id)
        XCTAssertThrowsError(try b.entry(for: a.identifier(for: entry)))
        XCTAssertThrowsError(try AutoFillSnapshot(keyInfo: Data(), entries: [entry, entry]))
        XCTAssertThrowsError(try AutoFillSnapshot(keyInfo: Data(), entries: [.init(id: "x", ciphertext: Data(count: AutoFillSnapshot.maxEntryBytes + 1))]))
    }

    func testScanDoesNotFollowSymlinksAndSkipsMetadata() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let outside = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let fm = FileManager.default
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        try fm.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root); try? fm.removeItem(at: outside) }
        try Data([1]).write(to: root.appendingPathComponent("example.com.gpg"))
        try Data([2]).write(to: outside.appendingPathComponent("secret.gpg"))
        try Data([3]).write(to: root.appendingPathComponent(".hidden.gpg"))
        try fm.createSymbolicLink(at: root.appendingPathComponent("linked.gpg"), withDestinationURL: outside.appendingPathComponent("secret.gpg"))
        try fm.createSymbolicLink(at: root.appendingPathComponent("directory"), withDestinationURL: outside)
        XCTAssertEqual(try AutoFillSnapshot.scan(root: root).map(\.id), ["example.com"])
        XCTAssertThrowsError(try AutoFillSnapshot.scan(root: root.appendingPathComponent("directory")))
    }
}
