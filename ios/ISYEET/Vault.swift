import Foundation
import Security

struct Vault {
    private let scope: AccountStorageScope
    init(server: URL) throws { scope = try AccountStorageScope(server: server) }
    private let account = "only-device"

    func load() throws -> StoredAccount? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 8 * 1024 * 1024 else { throw SafetyError.persistence }
        let stored: StoredAccount
        do { stored = try JSONDecoder().decode(StoredAccount.self, from: data) }
        catch { throw SafetyError.persistence }
        guard stored.version == 1, try MessageSafety.canonicalEmail(stored.email) == stored.email else { throw SafetyError.persistence }
        try scope.validate(backend: stored.backend)
        return stored
    }

    func save(_ value: StoredAccount) throws {
        try scope.validate(backend: value.backend)
        guard value.unreadMessageIDs.count <= UnreadMessages.maximumCount else { throw SafetyError.persistence }
        let data = try JSONEncoder().encode(value)
        guard data.count <= 8 * 1024 * 1024 else { throw SafetyError.persistence }
        // A single Keychain update is the transaction boundary for ratchets, inbox,
        // outbox, unread IDs, dedupe records and the server token. Never adopt before success.
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let update = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if update == errSecItemNotFound {
            var new = baseQuery
            attributes.forEach { new[$0.key] = $0.value }
            guard SecItemAdd(new as CFDictionary, nil) == errSecSuccess else { throw SafetyError.persistence }
        } else if update != errSecSuccess {
            throw SafetyError.persistence
        }
    }

    func loadOperation() throws -> AccountOperation? {
        var query = operationQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 8 * 1024 * 1024 else { throw SafetyError.persistence }
        do {
            let operation = try JSONDecoder().decode(AccountOperation.self, from: data).validated()
            try scope.validate(backend: operation.backend)
            return operation
        }
        catch { throw SafetyError.persistence }
    }

    func saveOperation(_ operation: AccountOperation) throws {
        try scope.validate(backend: operation.backend)
        let data = try JSONEncoder().encode(operation.validated())
        guard data.count <= 8 * 1024 * 1024 else { throw SafetyError.persistence }
        let attributes: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let status = SecItemUpdate(operationQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var query = operationQuery
            attributes.forEach { query[$0.key] = $0.value }
            guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw SafetyError.persistence }
        } else if status != errSecSuccess { throw SafetyError.persistence }
    }

    func deleteAccount() throws { try delete(baseQuery) }
    func clearOperation() throws { try delete(operationQuery) }
    private func delete(_ query: [String: Any]) throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SafetyError.persistence }
    }
    private var operationQuery: [String: Any] {
        var query = baseQuery
        query[kSecAttrAccount as String] = "pending-account-operation"
        return query
    }

    private var baseQuery: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: scope.service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }
}
