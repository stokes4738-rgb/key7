import Foundation
import Security

struct StoredCredential: Codable {
    var rpID: String
    var credentialID: Data
    var userID: Data
    var privateKey: Data // P256 scalar, encrypted by iOS Keychain, device-only
    var signatureCount: UInt32
}

enum VaultError: Error {
    case keychain(OSStatus)
    case corruptData
    case credentialMissing
}

final class CredentialVault {
    private let service = "org.key7.fido-lab.credentials.v1"
    private let account = "credential-list"

    func all() throws -> [StoredCredential] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
        guard let saved = result as? Data,
              let records = try? JSONDecoder().decode([StoredCredential].self, from: saved) else {
            throw VaultError.corruptData
        }
        return records
    }

    private func save(_ records: [StoredCredential]) throws {
        let encoded = try JSONEncoder().encode(records)
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let updated = SecItemUpdate(base as CFDictionary,
                                    [kSecValueData as String: encoded] as CFDictionary)
        if updated == errSecSuccess { return }
        if updated != errSecItemNotFound { throw VaultError.keychain(updated) }
        var add = base
        add[kSecValueData as String] = encoded
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess else { throw VaultError.keychain(added) }
    }

    func insert(_ credential: StoredCredential) throws {
        var records = try all()
        records.append(credential)
        try save(records)
    }

    func find(rpID: String, id: Data) throws -> StoredCredential? {
        try all().first { $0.rpID == rpID && $0.credentialID == id }
    }

    func bumpCounter(rpID: String, id: Data) throws -> StoredCredential {
        var records = try all()
        guard let index = records.firstIndex(where: { $0.rpID == rpID && $0.credentialID == id }) else {
            throw VaultError.credentialMissing
        }
        records[index].signatureCount = records[index].signatureCount == UInt32.max ? UInt32.max : records[index].signatureCount + 1
        let changed = records[index]
        try save(records)
        return changed
    }
}
