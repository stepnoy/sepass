import Foundation

/// The pass convention, not a new on-disk format. Never persist this plaintext type.
public struct AutoFillLogin {
    public let username: String
    public let password: String

    public init(plaintext: Data, fallbackUsername: String) throws {
        guard let text = String(data: plaintext, encoding: .utf8), !text.contains("\0") else {
            throw AutoFillDataError.invalidEntry
        }
        let lines = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
        guard let first = lines.first, !first.isEmpty else { throw AutoFillDataError.invalidEntry }
        password = first // Whitespace can be part of a password.
        username = lines.dropFirst().compactMap { line -> String? in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let field = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            guard ["login", "username", "user"].contains(field) else { return nil }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }.first ?? fallbackUsername
    }
}

public enum AutoFillDataError: Error {
    case invalidEntry, invalidPath, tooLarge, invalidSnapshot, staleIdentity
}

public enum AutoFillPath {
    public static func isSafe(_ path: String) -> Bool {
        guard path.utf8.count <= 4096, path.split(separator: "/").count <= 128, !path.isEmpty, !path.hasPrefix("/"), !path.contains("\\"),
              !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return false }
        return path.split(separator: "/", omittingEmptySubsequences: false)
            .allSatisfy { !$0.isEmpty && !$0.hasPrefix(".") }
    }

    /// Exact ASCII DNS names only. Avoid substring, suffix, URL-userinfo and path matching.
    public static func domain(_ value: String) -> String? {
        let lowered = value.lowercased()
        let host = lowered.hasSuffix(".") ? String(lowered.dropLast()) : lowered
        guard host.utf8.count <= 253, host.contains("."),
              host.unicodeScalars.allSatisfy({ $0.isASCII }) else { return nil }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ label in
            !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-") &&
            label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }), let last = labels.last, last.utf8.contains(where: { (97...122).contains($0) }) else { return nil }
        return host
    }

    public static func domains(in path: String) -> [String] {
        guard isSafe(path) else { return [] }
        return Array(Set(path.split(separator: "/").compactMap { domain(String($0)) })).sorted()
    }
}

public struct AutoFillEncryptedEntry: Codable, Identifiable {
    public let id: String // Relative path, without .gpg
    public let ciphertext: Data
    public var domains: [String] { AutoFillPath.domains(in: id) }
    public var label: String { (id as NSString).lastPathComponent }

    public init(id: String, ciphertext: Data) {
        self.id = id; self.ciphertext = ciphertext
    }
}

public struct AutoFillSnapshot: Codable {
    public static let maxEntryBytes = 1_048_576
    public static let maxCiphertextBytes = 16_777_216
    public static let maxEncodedBytes = 25_165_824
    public static let maxEntries = 10_000
    public let version: Int
    public let generation: UUID
    public let keyInfo: Data // Public key description, never private material.
    public let entries: [AutoFillEncryptedEntry]

    public init(keyInfo: Data, entries: [AutoFillEncryptedEntry]) throws {
        version = 1; generation = UUID(); self.keyInfo = keyInfo; self.entries = entries
        try validate()
    }

    public func validate() throws {
        guard version == 1, entries.count <= Self.maxEntries, keyInfo.count <= 65_536,
              Set(entries.map(\.id)).count == entries.count else { throw AutoFillDataError.invalidSnapshot }
        var total = 0
        for entry in entries {
            guard AutoFillPath.isSafe(entry.id) else { throw AutoFillDataError.invalidPath }
            guard !entry.ciphertext.isEmpty, entry.ciphertext.count <= Self.maxEntryBytes else {
                throw AutoFillDataError.tooLarge
            }
            total += entry.ciphertext.count
            guard total <= Self.maxCiphertextBytes else { throw AutoFillDataError.tooLarge }
        }
    }

    public func identifier(for entry: AutoFillEncryptedEntry) -> String {
        generation.uuidString + ":" + entry.id
    }

    public func entry(for identifier: String) throws -> AutoFillEncryptedEntry {
        let prefix = generation.uuidString + ":"
        guard identifier.hasPrefix(prefix),
              let entry = entries.first(where: { $0.id == String(identifier.dropFirst(prefix.count)) }) else {
            throw AutoFillDataError.staleIdentity
        }
        return entry
    }

    /// No symlinks, including symlinked directories. The caller owns this local checkout.
    public static func scan(root: URL) throws -> [AutoFillEncryptedEntry] {
        let fm = FileManager.default
        let rootValues = try root.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey])
        guard rootValues.isSymbolicLink != true, rootValues.isDirectory == true else {
            throw AutoFillDataError.invalidPath
        }
        var result: [AutoFillEncryptedEntry] = []
        var total = 0
        func visit(_ directory: URL, prefix: String) throws {
            for url in try fm.contentsOfDirectory(at: directory,
                includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey, .fileSizeKey],
                options: [.skipsHiddenFiles]) {
                let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey, .fileSizeKey])
                guard values.isSymbolicLink != true else { continue }
                let path = prefix + url.lastPathComponent
                guard AutoFillPath.isSafe(path) else { throw AutoFillDataError.invalidPath }
                if values.isDirectory == true {
                    try visit(url, prefix: path + "/")
                } else if values.isRegularFile == true, path.hasSuffix(".gpg") {
                    guard (values.fileSize ?? 0) <= maxEntryBytes, result.count < maxEntries else {
                        throw AutoFillDataError.tooLarge
                    }
                    let data = try Data(contentsOf: url)
                    total += data.count
                    guard !data.isEmpty, data.count <= maxEntryBytes, total <= maxCiphertextBytes else {
                        throw AutoFillDataError.tooLarge
                    }
                    result.append(AutoFillEncryptedEntry(id: String(path.dropLast(4)), ciphertext: data))
                }
            }
        }
        try visit(root, prefix: "")
        return result.sorted { $0.id < $1.id }
    }
}
