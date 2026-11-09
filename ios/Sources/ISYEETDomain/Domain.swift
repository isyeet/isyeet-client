import Foundation

public enum SafetyError: Error, LocalizedError, Equatable {
    case deviceAuthorizationUnavailable, deviceAuthorizationConflict, invalidPairingRequest, deviceIdentityReplaced, accountOperationConflict, trafficUnavailable, invalidText, invalidGroup, invalidAccountID, selfContact, invalidFingerprint, staleContactVerification, unchangedFingerprint, invalidUsername, usernameUnavailable, invalidPasskeyLabel, legacyAccount, passkeyUnavailable, invalidResponse, insecureServer, persistence, configuration, accountMismatch, identityAlreadyRegistered, unauthorized, network

    public var errorDescription: String? {
        switch self {
        case .deviceAuthorizationUnavailable: "Device approval is not enabled in this build. This phone remains the only messaging device."
        case .deviceAuthorizationConflict: "The device list changed or the approval expired. Refresh before reviewing another request."
        case .invalidPairingRequest: "The pairing request is invalid or expired. Copy a new complete request from the other device."
        case .deviceIdentityReplaced: "DEVICE REGISTRATION MISSING OR CHANGED. Messaging is stopped. Clear this device only if you intend to re-enroll; contacts must independently verify any new keys."
        case .accountOperationConflict: "The account changed or this operation expired. No new operation was started. Retry the saved operation or contact support."
        case .trafficUnavailable: "The server could not confirm the traffic mode. Cover traffic is paused. Refresh to retry."
        case .invalidText: "Only 1–1024 printable ASCII characters are allowed. No Unicode, newlines, tabs, or control characters."
        case .invalidGroup: "Choose 1–7 independently verified contacts and a group title of 1–48 printable ASCII characters. Membership cannot change."
        case .invalidAccountID: "The account identifier is invalid. Add a contact by their username."
        case .selfContact: "Use Message yourself on the main screen to test delivery to this device."
        case .invalidFingerprint: "Enter the full 64-character fingerprint obtained from this person outside ISYEET."
        case .staleContactVerification: "This contact's saved verification changed. Close this screen and start again."
        case .unchangedFingerprint: "That is the saved fingerprint. A re-enrolled contact must provide their new fingerprint outside ISYEET."
        case .invalidUsername: "Use 3–24 lowercase ASCII letters, numbers or underscores; start with a letter."
        case .usernameUnavailable: "That username is unavailable. Choose another, or sign in with your existing passkey."
        case .invalidPasskeyLabel: "Name the passkey using 1–32 printable ASCII characters."
        case .legacyAccount: "This device contains an earlier email-based account. Version 2 uses usernames and passkeys. Clear the old local account explicitly before creating a new identity. Old keys and contacts cannot migrate."
        case .passkeyUnavailable: "The passkey request could not be completed. Try again, or use another registered passkey."
        case .invalidResponse: "Security alert: an invalid message or response was rejected."
        case .insecureServer: "An HTTPS server address is required."
        case .persistence: "Secure storage could not be saved. No new message was sent or acknowledged. Unlock your device and try again."
        case .configuration: "The service and passkey domain configuration must match before signing in."
        case .accountMismatch: "This installation belongs to a different account or server. Sign in with the original account’s passkey."
        case .identityAlreadyRegistered: "This account already has a device identity. If you lost that device, choose Re-enroll this device. Your contacts must remove the old contact and independently verify your new keys."
        case .unauthorized: "Sign in again with the same account’s passkey. Your encryption keys remain on this device."
        case .network: "The request could not be completed. Refresh when connected to retry pending delivery."
        }
    }
}

// Only the authenticated key endpoint's explicit absence response permits a
// fresh installation to create keys. No public key material needs decoding.
enum AccountRegistration {
    static func requireUnregistered(statusCode: Int, body: Data) throws {
        switch statusCode {
        case 200: throw SafetyError.identityAlreadyRegistered
        case 401: throw SafetyError.unauthorized
        case 404:
            guard let error = try? JSONDecoder().decode([String: String].self, from: body),
                  error == ["error": "not found"] else { throw SafetyError.invalidResponse }
        default: throw SafetyError.network
        }
    }
}

public enum MessageSafety {
    public static let maximumBytes = 1024

    // Inspect raw bytes before constructing any string from decrypted data.
    public static func decode(_ bytes: Data) throws -> String {
        guard !bytes.isEmpty, bytes.count <= maximumBytes, bytes.allSatisfy({ (0x20...0x7e).contains($0) }) else {
            throw SafetyError.invalidText
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    public static func validate(_ text: String) throws {
        _ = try decode(Data(text.utf8))
    }

    public static func canonicalAccountID(_ value: String) throws -> String {
        guard let id = UUID(uuidString: value), value == id.uuidString.lowercased(),
              id.uuid.6 >> 4 == 4, id.uuid.8 >> 6 == 2 else { throw SafetyError.invalidAccountID }
        return value
    }

    public static func canonicalUsername(_ value: String) throws -> String {
        let bytes = Array(value.utf8)
        guard (3...24).contains(bytes.count), let first = bytes.first, (97...122).contains(first),
              bytes.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }) else {
            throw SafetyError.invalidUsername
        }
        return value
    }

    public static func serverURL(_ input: String, allowLoopbackHTTP: Bool = false) throws -> URL {
        guard let components = URLComponents(string: input), let url = components.url,
              let host = components.host, !host.isEmpty, components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil,
              components.path.isEmpty || components.path == "/" else { throw SafetyError.insecureServer }
        let loopback = ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host.lowercased())
        guard components.scheme == "https" || (allowLoopbackHTTP && loopback && components.scheme == "http") else {
            throw SafetyError.insecureServer
        }
        return url
    }

    public static func validFingerprint(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

// A build selects one fixed relay. Labels cannot conceal a different origin.
enum ServiceEnvironment: String, Sendable {
    case staging, production, local
    var title: String {
        switch self { case .staging: "Staging"; case .production: "Production"; case .local: "Local development" }
    }
    init(name: String, server: URL, allowLocal: Bool) throws {
        guard let environment = Self(rawValue: name) else { throw SafetyError.configuration }
        switch environment {
        case .staging:
            guard server.absoluteString == "https://api-staging.isyeet.io" else { throw SafetyError.configuration }
        case .production:
            guard server.absoluteString == "https://api.isyeet.io" else { throw SafetyError.configuration }
        case .local:
            guard allowLocal, server.scheme == "http", ["127.0.0.1", "localhost", "::1", "[::1]"].contains(server.host ?? "") else { throw SafetyError.configuration }
        }
        self = environment
    }
}

// Staging keeps its original Keychain item in place. Every other origin has an
// independent account AND operation journal; no keys/history are copied/deleted.
struct AccountStorageScope: Equatable {
    let backend: String
    let service: String
    init(server: URL) throws {
        backend = try MessageSafety.serverURL(server.absoluteString, allowLoopbackHTTP: true).absoluteString
        service = backend == "https://api-staging.isyeet.io"
            ? "com.isyeet.app.account.v1"
            : "com.isyeet.app.account.v2.origin:" + backend
    }
    func validate(backend stored: String) throws {
        guard stored == backend else { throw SafetyError.accountMismatch }
    }
}

// Preserve the Rust state as opaque JSON. No Swift code modifies its contents.
public enum JSONValue: Codable, Equatable, Sendable {
    case object([String: JSONValue]), array([JSONValue]), string(String), integer(Int64), unsigned(UInt64), number(Double), bool(Bool), null

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Int64.self) { self = .integer(value) }
        else if let value = try? container.decode(UInt64.self) { self = .unsigned(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([String: JSONValue].self) { self = .object(value) }
        else { self = .array(try container.decode([JSONValue].self)) }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .unsigned(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    public func decoded<T: Decodable>(_ type: T.Type) throws -> T {
        try JSONDecoder().decode(type, from: JSONEncoder().encode(self))
    }
}

public struct Contact: Codable, Identifiable, Equatable, Sendable {
    public let account_id: String
    public let username: String
    public let fingerprint: String
    public let verified: Bool
    public var id: String { account_id }
}

// Capture the exact old pin when opening a removal confirmation.
struct ContactRemoval: Identifiable, Equatable, Sendable {
    let account_id: String
    let previousFingerprint: String
    var id: String { account_id + ":" + previousFingerprint }
    init(contact: Contact) { account_id = contact.account_id; previousFingerprint = contact.fingerprint }
    func validate(current: Contact?) throws {
        guard (try? MessageSafety.canonicalAccountID(account_id)) == account_id,
              MessageSafety.validFingerprint(previousFingerprint), current?.account_id == account_id,
              current?.fingerprint == previousFingerprint else { throw SafetyError.staleContactVerification }
    }
}
enum ContactRemovalResult: Equatable { case removed, removedPendingSynchronization, failed(String) }

enum AccountOperationKind: String, Codable { case delete, reenroll }
struct AccountStateResponse: Decodable {
    let account_id: String
    let generation: String
    let identity_fingerprint: String?
    let server_time: Int64
    func validated(account_id expected: String) throws -> Self {
        guard account_id == expected, (try? MessageSafety.canonicalAccountID(account_id)) == account_id,
              Self.canonicalGeneration(generation), server_time > 0, server_time <= Int64.max - 900,
              identity_fingerprint.map(MessageSafety.validFingerprint) ?? true else { throw SafetyError.invalidResponse }
        return self
    }
    static func canonicalGeneration(_ value: String) -> Bool {
        guard let id = UUID(uuidString: value) else { return false }
        return value == id.uuidString.lowercased() && id.uuid.6 >> 4 == 4 && id.uuid.8 >> 6 == 2
    }
}
struct AccountCompletion: Decodable {
    let operation_id: String
    let account_id: String
    let completed: Bool
    func validate(_ operation: AccountOperation) throws {
        guard completed, operation_id == operation.operationID, account_id == operation.account_id else { throw SafetyError.invalidResponse }
    }
}
// Separate ThisDeviceOnly Keychain journal. The narrowly scoped action proof is
// retained so an uncertain deletion can retrieve its receipt after credentials disappear.
// Presence locks ordinary messaging until the same operation finishes safely.
struct AccountOperation: Codable, Equatable {
    let username: String
    var actionToken: String
    let kind: AccountOperationKind
    let backend: String
    let account_id: String
    let operationID: String
    let expiresAt: Int64
    let expectedGeneration: String
    let expectedFingerprint: String?
    let preparedCore: JSONValue?
    let preparedKeys: JSONValue?
    let preparedFingerprint: String?
    var completed = false
    var discardLocal = false

    func validated() throws -> Self {
        guard (try? MessageSafety.canonicalAccountID(account_id)) == account_id,
              (try? MessageSafety.canonicalUsername(username)) == username,
              !actionToken.isEmpty, actionToken.utf8.count <= 1024, actionToken.utf8.allSatisfy({ (0x21...0x7e).contains($0) }),
              AccountStateResponse.canonicalGeneration(operationID),
              AccountStateResponse.canonicalGeneration(expectedGeneration), expiresAt > 0,
              expectedFingerprint.map(MessageSafety.validFingerprint) ?? true else { throw SafetyError.persistence }
        if kind == .reenroll {
            guard let expectedFingerprint, let preparedFingerprint,
                  MessageSafety.validFingerprint(preparedFingerprint), preparedFingerprint != expectedFingerprint,
                  preparedCore != nil, case .object(let keys) = preparedKeys,
                  case .string(let key) = keys["identity_key"], !key.isEmpty else { throw SafetyError.persistence }
        } else {
            guard preparedCore == nil, preparedKeys == nil, preparedFingerprint == nil else { throw SafetyError.persistence }
        }
        return self
    }
    func request() -> JSONValue {
        var fields: [String: JSONValue] = ["action_token": .string(actionToken), "operation_id": .string(operationID),
            "expires_at": .integer(expiresAt), "expected_generation": .string(expectedGeneration),
            "expected_identity_fingerprint": expectedFingerprint.map(JSONValue.string) ?? .null]
        if let keys = preparedKeys { fields["keys"] = keys }
        return .object(fields)
    }
    func validateCurrentKeys(_ keys: JSONValue) throws {
        guard kind == .reenroll, case .object(let expected) = preparedKeys, case .object(let actual) = keys,
              Set(actual.keys) == Set(expected.keys),
              ["identity_key", "registration_id", "signed_pre_key", "kyber_pre_key"].allSatisfy({ expected[$0] != nil && expected[$0] == actual[$0] }),
              case .array(let original) = expected["pre_keys"], case .array(let remaining) = actual["pre_keys"] else {
            throw SafetyError.accountOperationConflict
        }
        var ids = Set<Int64>()
        for key in remaining {
            guard original.contains(key), case .object(let fields) = key,
                  case .integer(let id) = fields["id"], ids.insert(id).inserted else { throw SafetyError.accountOperationConflict }
        }
    }
}

public struct MessageGroup: Codable, Identifiable, Equatable, Sendable {
    public struct Member: Codable, Equatable, Sendable {
        public let account_id: String
        public let fingerprint: String
    }
    public let id: String
    public let title: String
    public let members: [Member]
    public let blocked: Bool
    public var conversationID: String { "group:" + id }

    public static func validateTitle(_ title: String) throws {
        guard (1...48).contains(title.utf8.count), title.utf8.allSatisfy({ (0x20...0x7e).contains($0) }) else {
            throw SafetyError.invalidGroup
        }
    }
}

public struct OutboxReference: Codable, Equatable, Sendable {
    public let id: String
    public let group_id: String
    public let message_id: String
    public let recipient: String
}

// Selection retains only an identifier. Every details render resolves the live
// snapshot, so expiry, contact replacement and failed storage remove its content.
struct MessageSelection: Identifiable, Equatable { let id: String }

public struct StoredMessage: Codable, Identifiable, Equatable, Sendable {
    public let id: String
    public let sender: String
    public let recipient: String
    public let text: String?
    public let security_alert: String?
    public let duplicate: Bool
    public let expires_at: Int64
    public let expired: Bool
    public let deferred: Bool
    public let cover: Bool
    public let group_id: String?
    public let logical_id: String?
    public let sent_at: Int64?
    public let received_at: Int64?
    public let sender_fingerprint: String?
    public let status: String?
    public let accepted_count: Int?
    public let recipient_count: Int?

    public init(id: String, sender: String, recipient: String, text: String?, security_alert: String?,
                duplicate: Bool, expires_at: Int64, expired: Bool = false, deferred: Bool = false, cover: Bool = false, group_id: String? = nil,
                logical_id: String? = nil, sent_at: Int64? = nil, received_at: Int64? = nil,
                sender_fingerprint: String? = nil, status: String? = nil,
                accepted_count: Int? = nil, recipient_count: Int? = nil) {
        self.id = id; self.sender = sender; self.recipient = recipient; self.text = text
        self.security_alert = security_alert; self.duplicate = duplicate
        self.expires_at = expires_at; self.expired = expired; self.deferred = deferred; self.cover = cover
        self.group_id = group_id; self.logical_id = logical_id; self.sent_at = sent_at
        self.received_at = received_at; self.sender_fingerprint = sender_fingerprint
        self.status = status; self.accepted_count = accepted_count; self.recipient_count = recipient_count
    }

    private enum CodingKeys: String, CodingKey {
        case id, sender, recipient, text, security_alert, duplicate, expires_at, expired, deferred, cover
        case group_id, logical_id, sent_at, received_at, sender_fingerprint, status, accepted_count, recipient_count
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        sender = try values.decode(String.self, forKey: .sender)
        recipient = try values.decode(String.self, forKey: .recipient)
        text = try values.decodeIfPresent(String.self, forKey: .text)
        security_alert = try values.decodeIfPresent(String.self, forKey: .security_alert)
        duplicate = try values.decode(Bool.self, forKey: .duplicate)
        expires_at = try values.decodeIfPresent(Int64.self, forKey: .expires_at) ?? 0
        expired = try values.decodeIfPresent(Bool.self, forKey: .expired) ?? false
        deferred = try values.decodeIfPresent(Bool.self, forKey: .deferred) ?? false
        cover = try values.decodeIfPresent(Bool.self, forKey: .cover) ?? false
        group_id = try values.decodeIfPresent(String.self, forKey: .group_id)
        logical_id = try values.decodeIfPresent(String.self, forKey: .logical_id)
        sent_at = try values.decodeIfPresent(Int64.self, forKey: .sent_at)
        received_at = try values.decodeIfPresent(Int64.self, forKey: .received_at)
        sender_fingerprint = try values.decodeIfPresent(String.self, forKey: .sender_fingerprint)
        status = try values.decodeIfPresent(String.self, forKey: .status)
        accepted_count = try values.decodeIfPresent(Int.self, forKey: .accepted_count)
        recipient_count = try values.decodeIfPresent(Int.self, forKey: .recipient_count)
    }

    // A second display guard; the Rust core authenticates and prunes deadlines.
    public func isRetained(at now: Int64) -> Bool { !expired && !deferred && !cover && expires_at > now }

    public func conversationID(accountID: String) -> String {
        if let group_id { return "group:" + group_id }
        return sender == accountID ? recipient : sender
    }

    // Only new authenticated records carry these fields. Do not infer a sent
    // time or historical sender key from legacy records or rejected ciphertext.
    public var authenticatedSentAt: Int64? { text != nil && security_alert == nil ? sent_at : nil }
    public var historicalFingerprint: String? { text != nil && security_alert == nil ? sender_fingerprint : nil }
    public var deliveryDescription: String {
        switch status {
        case "queued": "Queued on this device"
        case "partially_accepted": "Partially accepted by relay"
        case "relay_accepted": "Accepted by relay"
        case "received": "Received on this device"
        case "cancelled": "Cancelled"
        default: "Not recorded"
        }
    }
}

public struct SendRequest: Codable, Sendable {
    public let id: String
    public let recipient: String
    public let envelope: String
    public let expires_at: Int64

    public init(id: String, recipient: String, envelope: String, expires_at: Int64) {
        self.id = id
        self.recipient = recipient
        self.envelope = envelope
        self.expires_at = expires_at
    }

    private enum CodingKeys: String, CodingKey { case id, recipient, envelope, expires_at }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        recipient = try values.decode(String.self, forKey: .recipient)
        envelope = try values.decode(String.self, forKey: .envelope)
        expires_at = try values.decodeIfPresent(Int64.self, forKey: .expires_at) ?? 0
    }
}

public struct QueuedMessage: Codable, Sendable {
    public let id: String
    public let sender: String
    public let envelope: String
    public let created_at: Int64
}

public enum TrafficMode: String, CaseIterable, Identifiable {
    case notifications, cover
    public var id: String { rawValue }
    public var title: String { self == .cover ? "Cover traffic" : "Notifications" }
}

public struct TrafficState: Codable, Sendable {
    public var enabled: Bool = false
    public var eligible_contacts: [String] = []
    public var remaining_budget: Int = 4096
    public var cover_outbox_ids: [String] = []
    public var outstanding: Int = 0
    public init() {}
}

struct TrafficModeResponse: Decodable {
    let cover: Bool
    let notifications_resume_at: Int64?
    let server_time: Int64

    func validated() throws -> Self {
        guard server_time > 0, cover ? notifications_resume_at == nil : (notifications_resume_at ?? -1) >= 0 else {
            throw SafetyError.invalidResponse
        }
        return self
    }
}

enum TrafficClock {
    static func elapsedSeconds(from start: ContinuousClock.Instant, to end: ContinuousClock.Instant) throws -> Int64 {
        let elapsed = start.duration(to: end)
        guard elapsed >= .zero, elapsed <= .seconds(60) else { throw SafetyError.trafficUnavailable }
        let parts = elapsed.components
        return parts.seconds + (parts.attoseconds > 0 ? 1 : 0)
    }
}

// One independent monotonic clock. Calling arm for user activity never moves
// an existing deadline. A late slot schedules from now; there is no catch-up.
struct CoverCadence {
    private(set) var deadline: ContinuousClock.Instant?
    mutating func arm(now: ContinuousClock.Instant, delay: Duration) {
        if deadline == nil { deadline = now.advanced(by: delay) }
    }
    mutating func consume(now: ContinuousClock.Instant, nextDelay: Duration) -> Bool {
        guard let deadline, now >= deadline else { return false }
        self.deadline = now.advanced(by: nextDelay)
        return true
    }
    mutating func stop() { deadline = nil }
}

enum MessageTransport {
    static let bodyBytes = 12_288
    static func paddedBody(_ envelope: SendRequest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        var body = try encoder.encode(envelope)
        guard body.count <= bodyBytes else { throw SafetyError.invalidResponse }
        body.append(Data(repeating: 0x20, count: bodyBytes - body.count))
        return body
    }
}

public struct KeyMaintenanceState: Codable, Sendable {
    public let pending: JSONValue?
    public let next_check_at: Int64
    public let initial_upload_pending: Bool
    public init(pending: JSONValue? = nil, next_check_at: Int64 = Int64.max, initial_upload_pending: Bool = false) {
        self.pending = pending; self.next_check_at = next_check_at; self.initial_upload_pending = initial_upload_pending
    }
    private enum CodingKeys: String, CodingKey { case pending, next_check_at, initial_upload_pending }
    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        pending = try values.decodeIfPresent(JSONValue.self, forKey: .pending)
        next_check_at = try values.decode(Int64.self, forKey: .next_check_at)
        initial_upload_pending = try values.decodeIfPresent(Bool.self, forKey: .initial_upload_pending) ?? false
    }
}

public struct Snapshot: Codable, Sendable {
    public let account_id: String
    public let username: String
    public let fingerprint: String
    public let contacts: [Contact]
    public let outbox: [SendRequest]
    public let messages: [StoredMessage]
    public let groups: [MessageGroup]
    public let outbox_refs: [OutboxReference]
    public let pending_group_senders: [String]
    public let resolved_message_ids: [String]
    public let next_expiry: Int64?
    public let traffic: TrafficState
    public let key_maintenance: KeyMaintenanceState

    public init(account_id: String, username: String, fingerprint: String, contacts: [Contact], outbox: [SendRequest], messages: [StoredMessage],
                groups: [MessageGroup] = [], outbox_refs: [OutboxReference] = [], pending_group_senders: [String] = [], resolved_message_ids: [String] = [], next_expiry: Int64? = nil, traffic: TrafficState = TrafficState(), key_maintenance: KeyMaintenanceState = KeyMaintenanceState()) {
        self.account_id = account_id; self.username = username; self.fingerprint = fingerprint; self.contacts = contacts
        self.outbox = outbox; self.messages = messages; self.groups = groups; self.outbox_refs = outbox_refs
        self.pending_group_senders = pending_group_senders; self.resolved_message_ids = resolved_message_ids; self.next_expiry = next_expiry; self.traffic = traffic; self.key_maintenance = key_maintenance
    }

    private enum CodingKeys: String, CodingKey { case account_id, username, fingerprint, contacts, outbox, messages, groups, outbox_refs, pending_group_senders, resolved_message_ids, next_expiry, traffic, key_maintenance }
    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        account_id = try values.decode(String.self, forKey: .account_id)
        username = try values.decode(String.self, forKey: .username)
        fingerprint = try values.decode(String.self, forKey: .fingerprint)
        contacts = try values.decode([Contact].self, forKey: .contacts)
        outbox = try values.decode([SendRequest].self, forKey: .outbox)
        messages = try values.decode([StoredMessage].self, forKey: .messages)
        groups = try values.decodeIfPresent([MessageGroup].self, forKey: .groups) ?? []
        outbox_refs = try values.decodeIfPresent([OutboxReference].self, forKey: .outbox_refs) ?? []
        pending_group_senders = try values.decodeIfPresent([String].self, forKey: .pending_group_senders) ?? []
        resolved_message_ids = try values.decodeIfPresent([String].self, forKey: .resolved_message_ids) ?? []
        next_expiry = try values.decodeIfPresent(Int64.self, forKey: .next_expiry)
        traffic = try values.decodeIfPresent(TrafficState.self, forKey: .traffic) ?? TrafficState()
        key_maintenance = try values.decodeIfPresent(KeyMaintenanceState.self, forKey: .key_maintenance) ?? KeyMaintenanceState()
    }

    public func message(id: String, at now: Int64) -> StoredMessage? {
        messages.first { $0.id == id && $0.isRetained(at: now) }
    }

    public func messages(in conversation: String, at now: Int64) -> [StoredMessage] {
        messages.filter { message in
            guard message.isRetained(at: now) else { return false }
            if conversation.hasPrefix("group:") { return message.group_id.map { "group:" + $0 } == conversation }
            guard message.group_id == nil else { return false }
            if conversation == account_id { return message.sender == account_id && message.recipient == account_id }
            return (message.sender == account_id && message.recipient == conversation)
                || (message.sender == conversation && message.recipient == account_id)
        }
    }

    public func retained(at now: Int64) -> Self {
        let remaining = outbox.filter { $0.expires_at > now }
        var traffic = traffic
        traffic.cover_outbox_ids.removeAll { id in !remaining.contains { $0.id == id } }
        return Self(account_id: account_id, username: username, fingerprint: fingerprint, contacts: contacts,
                    outbox: remaining, messages: messages.filter { $0.isRetained(at: now) }, groups: groups,
                    outbox_refs: outbox_refs.filter { ref in remaining.contains { $0.id == ref.id } },
                    pending_group_senders: pending_group_senders, resolved_message_ids: resolved_message_ids,
                    next_expiry: next_expiry.flatMap { $0 > now ? $0 : nil }, traffic: traffic, key_maintenance: key_maintenance)
    }

    public var nextExpiry: Int64? {
        (messages.map(\.expires_at) + outbox.map(\.expires_at) + [next_expiry].compactMap { $0 }).filter { $0 > 0 }.min()
    }

    public func validated() throws -> Self {
        guard try MessageSafety.canonicalAccountID(account_id) == account_id,
              try MessageSafety.canonicalUsername(username) == username,
              MessageSafety.validFingerprint(fingerprint), contacts.count <= 64, outbox.count <= 16,
              messages.count <= 200, groups.count <= 32, outbox_refs.count <= 16,
              pending_group_senders.count <= 64, resolved_message_ids.count <= 64,
              pending_group_senders.allSatisfy({ (try? MessageSafety.canonicalAccountID($0)) == $0 }),
              resolved_message_ids.allSatisfy({ UUID(uuidString: $0) != nil }),
              Set(groups.map(\.id)).count == groups.count else { throw SafetyError.invalidResponse }
        guard key_maintenance.next_check_at >= 0 else { throw SafetyError.invalidResponse }
        if let pending = key_maintenance.pending {
            guard case .object(let request) = pending,
                  case .string(let operationID) = request["operation_id"], AccountStateResponse.canonicalGeneration(operationID),
                  case .integer(let generation) = request["expected_generation"], (0...Int64(UInt32.max - 1)).contains(generation),
                  case .object = request["keys"] else { throw SafetyError.invalidResponse }
        }
        guard (0...4096).contains(traffic.remaining_budget), (0...512).contains(traffic.outstanding),
              traffic.eligible_contacts.count <= 64, traffic.cover_outbox_ids.count <= 1,
              Set(traffic.eligible_contacts).count == traffic.eligible_contacts.count,
              traffic.eligible_contacts.allSatisfy({ candidate in candidate != account_id && contacts.contains { $0.account_id == candidate && $0.verified } }),
              traffic.cover_outbox_ids.allSatisfy({ id in UUID(uuidString: id) != nil && outbox.contains { $0.id == id } }) else {
            throw SafetyError.invalidResponse
        }
        for contact in contacts {
            guard try MessageSafety.canonicalAccountID(contact.account_id) == contact.account_id,
                  try MessageSafety.canonicalUsername(contact.username) == contact.username,
                  MessageSafety.validFingerprint(contact.fingerprint) else { throw SafetyError.invalidResponse }
        }
        for group in groups {
            try MessageGroup.validateTitle(group.title)
            guard MessageSafety.validFingerprint(group.id), (2...8).contains(group.members.count),
                  Set(group.members.map(\.account_id)).count == group.members.count,
                  group.members.contains(where: { $0.account_id == account_id && $0.fingerprint == fingerprint }) else { throw SafetyError.invalidResponse }
            for member in group.members {
                guard try MessageSafety.canonicalAccountID(member.account_id) == member.account_id,
                      MessageSafety.validFingerprint(member.fingerprint) else { throw SafetyError.invalidResponse }
            }
        }
        for ref in outbox_refs {
            guard UUID(uuidString: ref.id) != nil, UUID(uuidString: ref.message_id) != nil,
                  MessageSafety.validFingerprint(ref.group_id),
                  try MessageSafety.canonicalAccountID(ref.recipient) == ref.recipient else { throw SafetyError.invalidResponse }
        }
        for message in messages {
            guard UUID(uuidString: message.id) != nil,
                  try MessageSafety.canonicalAccountID(message.sender) == message.sender,
                  try MessageSafety.canonicalAccountID(message.recipient) == message.recipient else { throw SafetyError.invalidResponse }
            if let text = message.text { try MessageSafety.validate(text) }
            if let id = message.group_id { guard groups.contains(where: { $0.id == id }) else { throw SafetyError.invalidResponse } }
            if let id = message.logical_id { guard UUID(uuidString: id) != nil else { throw SafetyError.invalidResponse } }
            if let pin = message.sender_fingerprint { guard MessageSafety.validFingerprint(pin) else { throw SafetyError.invalidResponse } }
            if let sent = message.sent_at { guard message.expires_at > 604_800, sent > 0, sent == message.expires_at - 604_800 else { throw SafetyError.invalidResponse } }
            if let received = message.received_at { guard received > 0 else { throw SafetyError.invalidResponse } }
            if let status = message.status { guard ["queued", "partially_accepted", "relay_accepted", "received", "cancelled"].contains(status) else { throw SafetyError.invalidResponse } }
            if let accepted = message.accepted_count { guard (0...8).contains(accepted) else { throw SafetyError.invalidResponse } }
            if let total = message.recipient_count { guard (1...8).contains(total), (message.accepted_count ?? 0) <= total else { throw SafetyError.invalidResponse } }
        }
        return self
    }
}

public enum ConversationKind: String, Equatable, Sendable {
    case direct, selfMessage, group
}

/// A view of retained local records, never an additional plaintext store.
/// Resolve this from the latest snapshot whenever the inbox is rendered.
public struct ConversationSummary: Identifiable, Equatable, Sendable {
    public let id: String
    public let kind: ConversationKind
    public let title: String
    public let preview: String
    /// Trusted author metadata, separate from the literal preview body. UI must
    /// not infer direction from text such as a peer-written "You:" prefix.
    public let previewSender: String?
    /// The preview record's authenticated sent time, if it was recorded.
    /// An undated latest record must not borrow a previous message's date.
    public let activityAt: Int64?
    public let unreadCount: Int
    /// Logical messages, not the number of recipient copies in group fanout.
    public let queuedCount: Int
    public let latestMessageID: String?
    public let blocked: Bool

    public var queuedDescription: String? {
        guard queuedCount > 0 else { return nil }
        if kind == .selfMessage {
            return queuedCount == 1 ? "Awaiting return" : "\(queuedCount) awaiting return"
        }
        return queuedCount == 1 ? "1 message queued" : "\(queuedCount) messages queued"
    }
}

public extension Snapshot {
    /// Preview strings remain literal ASCII. UI must use verbatim text rendering.
    /// Outbox metadata never supplies plaintext or a fabricated activity date.
    func conversations(unreadCounts: [String: Int], at now: Int64) -> [ConversationSummary] {
        guard (try? MessageSafety.canonicalAccountID(account_id)) == account_id else { return [] }
        var descriptors: [String: (kind: ConversationKind, title: String, blocked: Bool)] = [
            account_id: (.selfMessage, "Message yourself", false),
        ]
        for contact in contacts where contact.account_id != account_id && (try? MessageSafety.canonicalAccountID(contact.account_id)) == contact.account_id {
            descriptors[contact.account_id] = (.direct, "@" + contact.username, !contact.verified)
        }
        var knownGroups: [String: MessageGroup] = [:]
        for group in groups where MessageSafety.validFingerprint(group.id)
            && (try? MessageGroup.validateTitle(group.title)) != nil
            && group.members.contains(where: { $0.account_id == account_id }) {
            descriptors[group.conversationID] = (.group, group.title, group.blocked)
            knownGroups[group.id] = group
        }

        var visible: [String: [StoredMessage]] = [:]
        var seenMessages = Set<String>()
        for message in messages {
            guard message.isRetained(at: now), !message.duplicate,
                  UUID(uuidString: message.id) != nil, seenMessages.insert(message.id).inserted else { continue }
            let conversation: String
            if let groupID = message.group_id {
                guard let group = knownGroups[groupID], message.recipient == account_id,
                      group.members.contains(where: { $0.account_id == message.sender }) else { continue }
                conversation = group.conversationID
            } else if message.sender == account_id {
                conversation = message.recipient
            } else if message.recipient == account_id {
                conversation = message.sender
            } else { continue }
            guard descriptors[conversation] != nil else { continue }
            // Empty machine dispositions cannot become conversation activity.
            guard message.text != nil || message.security_alert != nil else { continue }
            visible[conversation, default: []].append(message)
        }

        let coverIDs = Set(traffic.cover_outbox_ids)
        let references = Dictionary(grouping: outbox_refs, by: \.id)
        var pending: [String: Set<String>] = [:]
        for request in outbox where request.expires_at > now && !coverIDs.contains(request.id) && UUID(uuidString: request.id) != nil {
            if let refs = references[request.id] {
                // Invalid/ambiguous fanout metadata must never turn a group leg
                // into a direct conversation or reveal an unrelated peer row.
                guard refs.count == 1, let ref = refs.first,
                      ref.recipient == request.recipient, UUID(uuidString: ref.message_id) != nil,
                      let group = knownGroups[ref.group_id],
                      group.members.contains(where: { $0.account_id == request.recipient && $0.account_id != account_id }) else { continue }
                pending[group.conversationID, default: []].insert(ref.message_id)
            } else if descriptors[request.recipient]?.kind != .group,
                      descriptors[request.recipient] != nil {
                pending[request.recipient, default: []].insert(request.id)
            }
        }

        return descriptors.compactMap { id, descriptor in
            let records = visible[id] ?? []
            let queued = pending[id]?.count ?? 0
            guard descriptor.kind == .group || !records.isEmpty || queued > 0 else { return nil }
            let latest = records.last
            let preview: String
            let previewSender: String?
            let activity: Int64?
            if let latest {
                if latest.security_alert == nil, let text = latest.text,
                   (try? MessageSafety.validate(text)) != nil {
                    preview = text
                    previewSender = latest.sender
                    activity = latest.authenticatedSentAt.flatMap { $0 > 0 ? $0 : nil }
                } else {
                    preview = "Security alert: message rejected."
                    previewSender = nil
                    activity = nil
                }
            } else {
                preview = queued > 0
                    ? (descriptor.kind == .selfMessage ? "Awaiting return" : "Message queued")
                    : "No messages yet"
                previewSender = nil
                activity = nil
            }
            let unreadEligible = records.filter { message in
                message.sender != account_id && message.security_alert == nil
                    && message.text.map { (try? MessageSafety.validate($0)) != nil } == true
            }.count
            return ConversationSummary(id: id, kind: descriptor.kind, title: descriptor.title,
                                       preview: preview, previewSender: previewSender, activityAt: activity,
                                       unreadCount: min(max(unreadCounts[id] ?? 0, 0), unreadEligible),
                                       queuedCount: queued, latestMessageID: latest?.id, blocked: descriptor.blocked)
        }.sorted { first, second in
            switch (first.activityAt, second.activityAt) {
            case let (lhs?, rhs?) where lhs != rhs: return lhs > rhs
            case (_?, nil): return true
            case (nil, _?): return false
            default:
                if first.title != second.title { return first.title < second.title }
                return first.id < second.id
            }
        }
    }
}

// Device-local bookkeeping, stored with the opaque Signal state in one Keychain item.
struct StoredAccount: Codable, Equatable {
    let version: Int
    let backend: String
    let account_id: String
    let username: String
    var token: String
    var expiresAt: Int64
    var core: JSONValue
    var registered: Bool
    var unreadMessageIDs: [String]
    var contactIdentityChanges: [String]
    var identityReplaced: Bool

    init(version: Int, backend: String, account_id: String, username: String, token: String, expiresAt: Int64,
         core: JSONValue, registered: Bool, unreadMessageIDs: [String] = [], contactIdentityChanges: [String] = [], identityReplaced: Bool = false) {
        self.version = version
        self.backend = backend
        self.account_id = account_id
        self.username = username
        self.token = token
        self.expiresAt = expiresAt
        self.core = core
        self.registered = registered
        self.unreadMessageIDs = unreadMessageIDs
        self.identityReplaced = identityReplaced
        self.contactIdentityChanges = contactIdentityChanges
    }

    private enum CodingKeys: String, CodingKey {
        case version, backend, account_id, username, token, expiresAt, core, registered, unreadMessageIDs, contactIdentityChanges, identityReplaced
    }

    init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        version = try values.decode(Int.self, forKey: .version)
        guard version == 2 else { throw SafetyError.legacyAccount }
        backend = try values.decode(String.self, forKey: .backend)
        account_id = try values.decode(String.self, forKey: .account_id)
        username = try values.decode(String.self, forKey: .username)
        guard (try? MessageSafety.canonicalAccountID(account_id)) == account_id,
              (try? MessageSafety.canonicalUsername(username)) == username else { throw SafetyError.persistence }
        token = try values.decode(String.self, forKey: .token)
        expiresAt = try values.decode(Int64.self, forKey: .expiresAt)
        core = try values.decode(JSONValue.self, forKey: .core)
        registered = try values.decode(Bool.self, forKey: .registered)
        // An upgrade never marks historical messages unread.
        unreadMessageIDs = try values.decodeIfPresent([String].self, forKey: .unreadMessageIDs) ?? []
        guard unreadMessageIDs.count <= UnreadMessages.maximumCount else { throw SafetyError.persistence }
        identityReplaced = try values.decodeIfPresent(Bool.self, forKey: .identityReplaced) ?? false
        contactIdentityChanges = try values.decodeIfPresent([String].self, forKey: .contactIdentityChanges) ?? []
        guard contactIdentityChanges.count <= 64,
              contactIdentityChanges.allSatisfy({ (try? MessageSafety.canonicalAccountID($0)) == $0 }) else { throw SafetyError.persistence }
    }
}

struct MessageReadContext: Equatable {
    var appActive = false
    var visibleConversation: String?
    var covered = false

    var readableConversation: String? { appActive && !covered ? visibleConversation : nil }
}

enum UnreadMessages {
    static let maximumCount = 200

    static func updatedIDs(_ existing: [String], snapshot: Snapshot,
                           arrival: StoredMessage? = nil, arrivals: [StoredMessage] = [], reading: MessageReadContext,
                           now: Int64 = Int64(Date().timeIntervalSince1970)) -> [String] {
        let eligible = eligibleMessages(snapshot, now: now)
        var candidates = Set(existing.prefix(maximumCount))
        for arrival in arrivals + [arrival].compactMap({ $0 }) {
            if isEligible(arrival, accountID: snapshot.account_id, now: now),
               eligible.contains(where: { $0.id == arrival.id && $0.sender == arrival.sender }) {
                candidates.insert(arrival.id)
            }
        }
        var included = Set<String>()
        return eligible.compactMap { message in
            guard candidates.contains(message.id), message.conversationID(accountID: snapshot.account_id) != reading.readableConversation,
                  included.insert(message.id).inserted else { return nil }
            return message.id
        }
    }

    static func counts(_ ids: [String], snapshot: Snapshot, now: Int64 = Int64(Date().timeIntervalSince1970)) -> [String: Int] {
        let unread = Set(ids.prefix(maximumCount))
        var counted = Set<String>()
        var result: [String: Int] = [:]
        for message in eligibleMessages(snapshot, now: now) where unread.contains(message.id) && counted.insert(message.id).inserted {
            result[message.conversationID(accountID: snapshot.account_id), default: 0] += 1
        }
        return result
    }

    private static func eligibleMessages(_ snapshot: Snapshot, now: Int64) -> [StoredMessage] {
        snapshot.messages.suffix(maximumCount).filter { isEligible($0, accountID: snapshot.account_id, now: now) }
    }

    private static func isEligible(_ message: StoredMessage, accountID: String, now: Int64) -> Bool {
        guard message.sender != accountID, message.recipient == accountID,
              message.isRetained(at: now),
              !message.duplicate, message.security_alert == nil, UUID(uuidString: message.id) != nil,
              (try? MessageSafety.canonicalAccountID(message.sender)) == message.sender,
              let text = message.text else { return false }
        return (try? MessageSafety.validate(text)) != nil
    }
}

enum NotificationBadge {
    static func count(unread: Int, preservingRemoteHint: Bool, deliveredHint: Bool) -> Int {
        max(preservingRemoteHint && deliveredHint ? 1 : 0, min(max(unread, 0), UnreadMessages.maximumCount))
    }
}

public enum ASCIIFace: String, CaseIterable, Identifiable, Sendable {
    case happy = "(^_^)"
    case smile = ":-)"
    case wink = ";-)"
    case surprised = "(o_o)"
    case sad = ":("
    case love = "<3"
    case celebrate = "\\o/"
    case cat = "=^.^="

    public var id: String { rawValue }
    public var text: String { rawValue }

    public var name: String {
        switch self {
        case .happy: "Happy"
        case .smile: "Smile"
        case .wink: "Wink"
        case .surprised: "Surprised"
        case .sad: "Sad"
        case .love: "Love"
        case .celebrate: "Celebrate"
        case .cat: "Cat"
        }
    }

    /// Append ordinary message text without interpreting or normalizing the draft.
    public func appending(to draft: String) throws -> String {
        if !draft.isEmpty { try MessageSafety.validate(draft) }
        let separator = draft.isEmpty || draft.hasSuffix(" ") ? "" : " "
        let result = draft + separator + text
        try MessageSafety.validate(result)
        return result
    }
}

// Wire formats follow WebAuthn JSON. The app never parses or verifies authenticator
// signatures: AuthenticationServices creates them and the server verifies them.
struct PasskeyChallenge: Decodable {
    let challenge_id: String
    let account_id: String?
    let username: String?
    let public_key: PasskeyOptions
}
struct PasskeyOptions: Decodable {
    struct RelyingParty: Decodable { let id: String; let name: String }
    struct User: Decodable { let id: String; let name: String; let displayName: String }
    struct Descriptor: Decodable { let type: String; let id: String }
    struct Parameter: Decodable { let type: String; let alg: Int }
    let challenge: String
    let rp: RelyingParty?
    let rpId: String?
    let user: User?
    let excludeCredentials: [Descriptor]?
    let allowCredentials: [Descriptor]?
    let pubKeyCredParams: [Parameter]?
}
struct PasskeyAction: Decodable {
    let action_token: String
    let expires_at: Int64
}
struct RegisteredPasskey: Decodable, Identifiable, Equatable {
    let id: String
    let label: String
    let created_at: Int64
}
struct PasskeyList: Decodable {
    let passkeys: [RegisteredPasskey]
    let maximum: Int
}
struct DirectoryAccount: Decodable {
    let account_id: String
    let username: String
    func validated() throws -> Self {
        guard (try? MessageSafety.canonicalAccountID(account_id)) == account_id,
              (try? MessageSafety.canonicalUsername(username)) == username else { throw SafetyError.invalidResponse }
        return self
    }
}

extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    init?(base64URL: String) {
        guard !base64URL.isEmpty, base64URL.utf8.count <= 32768,
              base64URL.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { return nil }
        var value = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        self.init(base64Encoded: value)
        guard self.base64URL == base64URL else { return nil }
    }
}

// Deliberately absent from ordinary Debug, Release, and TestFlight builds.
// Authorization experiments do not enable a second messaging transport.
enum DeviceAuthorizationFeature {
    static var enabled: Bool {
        #if DEBUG && ISYEET_DEVICE_AUTHORIZATION_EXPERIMENT
        true
        #else
        false
        #endif
    }
}

struct DeviceAuthorityResponse: Decodable {
    let authority: JSONValue?
    let server_time: Int64
    let messaging_available: Bool

    func validated(now: Int64 = Int64(Date().timeIntervalSince1970)) throws -> Self {
        guard !messaging_available, server_time > 0,
              server_time >= now - 60, server_time <= now + 60 else { throw SafetyError.invalidResponse }
        return self
    }
}

struct DeviceAuthorityReceipt: Codable, Equatable {
    let operation_id: String
    let roster_version: UInt64
    let roster_hash: String
    let messaging_available: Bool

    func validated() throws -> Self {
        guard AccountStateResponse.canonicalGeneration(operation_id), roster_version > 0,
              roster_hash.utf8.count == 64, roster_hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              !messaging_available else { throw SafetyError.invalidResponse }
        return self
    }
}

// These checks bound display data only. The Rust core verifies signatures,
// transcript binding, expiry, and rollback protection before publishing it.
enum DevicePairingText {
    static let maximumBytes = 16_384
    static func validate(_ code: String, approval: Bool = false) throws {
        let prefix = approval ? "ISYEET-APPROVAL-1:" : "ISYEET-LINK-1:"
        guard code.utf8.count <= maximumBytes, code.hasPrefix(prefix),
              code.utf8.allSatisfy({ (0x21...0x7e).contains($0) }),
              let decoded = Data(base64URL: String(code.dropFirst(prefix.count))), !decoded.isEmpty else {
            throw SafetyError.invalidPairingRequest
        }
    }
    static func fingerprint(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    }
}

struct DeviceLinkInspection: Decodable, Equatable {
    let label: String
    let device_id: UInt32
    let identity_fingerprint: String
    let request_hash: String
    let expires_at: Int64
    let account_id: String
    let root_epoch: String

    func validated(accountID: String, now: Int64 = Int64(Date().timeIntervalSince1970)) throws -> Self {
        guard account_id == accountID, (2...127).contains(device_id),
              DeviceRosterMember.validLabel(label), DevicePairingText.fingerprint(identity_fingerprint),
              DevicePairingText.fingerprint(request_hash), expires_at > now, expires_at <= now + 360,
              !root_epoch.isEmpty, root_epoch.utf8.count <= 128,
              root_epoch.utf8.allSatisfy({ (0x21...0x7e).contains($0) }) else { throw SafetyError.invalidPairingRequest }
        return self
    }
}

struct DeviceRosterMember: Decodable, Identifiable {
    struct Certificate: Decodable {
        let account_id: String
        let root_epoch: String
        let device_id: UInt32
        let identity_key: String
        let registration_id: UInt32
        let label: String
        let request_hash: String
    }
    let certificate: Certificate
    let signature: String
    var id: UInt32 { certificate.device_id }
    static func validLabel(_ label: String) -> Bool {
        (1...32).contains(label.utf8.count) && label.utf8.allSatisfy({ (0x20...0x7e).contains($0) })
            && label == label.trimmingCharacters(in: .whitespaces) && !label.isEmpty
    }
}

struct DeviceSignedRoster: Decodable {
    struct Roster: Decodable {
        let origin: String
        let account_id: String
        let root_epoch: String
        let root_identity_key: String
        let version: UInt64
        let previous_hash: String
        let highest_device_id: UInt32
        let issued_at: Int64
        let expires_at: Int64
        let devices: [DeviceRosterMember]
    }
    let roster: Roster
    let signature: String

    func validated(accountID: String, origin: String) throws -> Self {
        let r = roster
        guard r.account_id == accountID, r.origin == origin, r.version > 0,
              (1...127).contains(r.highest_device_id), (1...2).contains(r.devices.count),
              r.issued_at > 0, r.expires_at > r.issued_at, r.expires_at - r.issued_at <= 86_400,
              Set(r.devices.map(\.id)).count == r.devices.count,
              let primary = r.devices.first(where: { $0.id == 1 }), primary.certificate.identity_key == r.root_identity_key,
              r.devices.allSatisfy({ member in
                  member.id >= 1 && member.id <= r.highest_device_id && member.certificate.account_id == accountID
                      && member.certificate.root_epoch == r.root_epoch && DeviceRosterMember.validLabel(member.certificate.label)
              }) else { throw SafetyError.invalidResponse }
        return self
    }
}

struct DeviceAuthoritySnapshot: Decodable {
    let authority: DeviceSignedRoster?
    let pending: JSONValue?
    let approval_code: String?
    let messaging_available: Bool

    func validated(accountID: String, origin: String) throws -> Self {
        guard !messaging_available else { throw SafetyError.invalidResponse }
        if let authority { _ = try authority.validated(accountID: accountID, origin: origin) }
        if let approval_code {
            guard authority != nil, pending == nil else { throw SafetyError.invalidResponse }
            try DevicePairingText.validate(approval_code, approval: true)
        }
        return self
    }
}
