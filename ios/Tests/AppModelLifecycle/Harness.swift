func testUsername(_ id: String) -> String {
    switch id {
    case "81d1a713-5b97-4257-bfb4-f094a2004296": "me_test"
    case "0beaac69-d53e-48d2-b5aa-dd405b7f414d": "alice"
    case "300db02d-b75a-4922-8759-f08a0efa5a40": "bob"
    case "c36e0493-49f8-4439-aa4c-2aa333bf235f": "carol"
    case "781e65af-8b81-4d42-9fef-a6bc1253f62f": "dave"
    case "9fa56b84-e436-4423-8452-b98816524ec5": "outsider"
    case "18ae18f2-64c2-4442-a0aa-fe2ef8d2d130": "other"
    case "ee9c5bcd-53b5-4939-b07a-8e021c7b6cfc": "elsewhere"
    case "5ff860bf-1190-496c-b188-ab851db691f0": "bob"
    case "75f4499b-5920-4d38-b057-e967e297590a": "a_test"
    default: "test_user"
    }
}

import Foundation

// Standalone regression harness compiled with the real Domain and AppModel.
// Every external adapter is synthetic and in-memory. This file is deliberately
// excluded from the Xcode app and the separate Swift package domain tests.

@MainActor enum Fixture {
    static var serverURL = URL(string: "https://example.com")!
    static var accounts: [String: StoredAccount] = [:]
    static var operations: [String: AccountOperation] = [:]
    static var operation: AccountOperation? {
        get { operations[serverURL.absoluteString] }
        set { operations[serverURL.absoluteString] = newValue }
    }
    static var failOperationSave = false
    static var failClearAccount = false
    static var failClearOperation = false
    static var authAccountID: String?
    static var registrationExists = false
    static var remoteFingerprint: String? = String(repeating: "a", count: 64)
    static var operationRequests: [AccountOperation] = []
    static var failRemoteOperation = false
    static var holdAccountOperation = false
    static var heldAccountOperation: CheckedContinuation<Void, Never>?
    static var mismatchOwnKeys = false
    static var failOwnKeys = false
    static var mismatchSignedKeys = false
    static var failReceiptSave = false
    static var conflictOperation = false
    static var remoteAbsent = false
    static var missingOwnKeys = false
    static var operationServerTime: Int64?
    static var remoteGeneration = "00000000-0000-4000-8000-000000000010"
    static var loginCalls = 0
    static var deviceAuthorityCalls = 0
    static var deviceNetworkEnabled = false
    static var deviceRemoteAuthority: JSONValue?
    static var deviceMutationCalls: [JSONValue] = []
    static var deviceProofs = 0
    static var deviceLoseReceipt = false
    static var deviceRejectMutation = false
    static var devicePendingExpired = false
    static func resetDeviceAuthorization() {
        deviceAuthorityCalls = 0; deviceNetworkEnabled = true; deviceRemoteAuthority = nil
        deviceMutationCalls = []; deviceProofs = 0; deviceLoseReceipt = false
        deviceRejectMutation = false; devicePendingExpired = false
    }
    static var uploads = 0
    static var failUpload = false
    static var pushUpdates = 0
    static var maintenanceReads = 0
    static var maintenanceRequests: [JSONValue] = []
    static var failMaintenance = false
    static var mismatchMaintenanceReceipt = false
    static var holdMaintenance = false
    static var heldMaintenance: CheckedContinuation<Void, Never>?
    static func keys(_ identity: String = "synthetic-new-key", remaining: Bool = false) -> JSONValue {
        .object(["identity_key": .string(identity), "registration_id": .integer(123),
            "signed_pre_key": .object(["id": .integer(1), "public_key": .string("signed"), "signature": .string("signature")]),
            "kyber_pre_key": .object(["id": .integer(2), "public_key": .string("kyber"), "signature": .string("signature")]),
            "pre_keys": .array(remaining ? [] : [.object(["id": .integer(3), "public_key": .string("prekey")])])])
    }
    static var heldPermissions: CheckedContinuation<Void, Never>?
    static var holdPermissions = false
    static var saved: StoredAccount? {
        get { accounts[serverURL.absoluteString] }
        set { accounts[serverURL.absoluteString] = newValue }
    }
    static var failSave = false
    static var writes = 0
    static var staleExpiryOnce = false
    static var delaySaveUntil: Int64?
    static var failAtWrite: Int?
    static var heldSend: CheckedContinuation<Void, Never>?
    static var heldClaim: CheckedContinuation<Void, Never>?
    static var holdSend = false
    static var holdClaim = false
    static var sent: [String] = []
    static var incoming: [QueuedMessage] = []
    static var acknowledgements = 0
    static var claimError = false
    static var claimBundle: JSONValue?
    static var rejectReplacement = false
    static var failPermissions = false
    static var permissionUpdates = 0
    static var identityChangedOnDecrypt = false
    static var selfMessages = false
    static var failSend = false
    static var rejectSelfReturn = false
    static var holdInbox = false
    static var heldInbox: CheckedContinuation<Void, Never>?
    static var keyClaims = 0
    static var failedRecipients = Set<String>()
    static var allowResolve = false
    static var deferredArrival: StoredMessage?
    static var directArrival: StoredMessage?
    static var resolutionGroup: MessageGroup?
    static var remoteCover = false
    static var failMode = false
    static var modeCalls: [Bool] = []
    static var coverArrives = false
    static var policyReads = 0
    static var confirmations = 0
    static var serverTimeOffset: Int64 = 0
    static var holdMode = false
    static var heldMode: CheckedContinuation<Void, Never>?
    static func reset(_ messages: [StoredMessage], outbox: [SendRequest] = [], sessionValid: Bool = false, contacts: [Contact] = [], groups: [MessageGroup] = [], refs: [OutboxReference] = [], traffic: TrafficState = TrafficState()) throws {
        serverURL = URL(string: "https://example.com")!; accounts = [:]; operations = [:]
        operation = nil; failOperationSave = false; failClearAccount = false; failClearOperation = false
        authAccountID = nil; registrationExists = false; remoteFingerprint = String(repeating: "a", count: 64)
        operationRequests = []; failRemoteOperation = false; holdAccountOperation = false; heldAccountOperation = nil
        mismatchOwnKeys = false; failOwnKeys = false; mismatchSignedKeys = false; failReceiptSave = false; holdPermissions = false; heldPermissions = nil
        conflictOperation = false; remoteAbsent = false; missingOwnKeys = false; operationServerTime = nil
        remoteGeneration = "00000000-0000-4000-8000-000000000010"; loginCalls = 0; uploads = 0; failUpload = false; pushUpdates = 0
        maintenanceReads = 0; maintenanceRequests = []; failMaintenance = false; mismatchMaintenanceReceipt = false; holdMaintenance = false; heldMaintenance = nil
        failSave = false; writes = 0; staleExpiryOnce = false; delaySaveUntil = nil; failAtWrite = nil; heldSend = nil; heldClaim = nil
        holdSend = false; holdClaim = false; sent = []; incoming = []; acknowledgements = 0
        claimError = false; claimBundle = nil; rejectReplacement = false; failPermissions = false; permissionUpdates = 0; identityChangedOnDecrypt = false
        selfMessages = false; failSend = false; rejectSelfReturn = false; holdInbox = false; heldInbox = nil; keyClaims = 0
        failedRecipients = []; allowResolve = false; deferredArrival = nil; directArrival = nil; resolutionGroup = nil
        remoteCover = false; failMode = false; modeCalls = []; coverArrives = false; holdMode = false; heldMode = nil; policyReads = 0; confirmations = 0; serverTimeOffset = 0
        let snapshot = Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64), contacts: contacts, outbox: outbox, messages: messages, groups: groups, outbox_refs: refs, traffic: traffic)
        saved = StoredAccount(version: 2, backend: "https://example.com", account_id: snapshot.account_id, username: testUsername(snapshot.account_id),
                              token: "synthetic", expiresAt: sessionValid ? Int64.max : 1,
                              core: .object(["snapshot": try json(snapshot), "identity": .string("unchanged synthetic key marker")]),
                              registered: true, unreadMessageIDs: messages.map(\.id))
    }
    static func json<T: Encodable>(_ value: T) throws -> JSONValue { try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(value)) }
    static func snapshot(_ state: JSONValue) throws -> Snapshot {
        guard case let .object(object) = state, let value = object["snapshot"] else { throw SafetyError.invalidResponse }
        return try value.decoded(Snapshot.self)
    }
    static func replacing(_ state: JSONValue, snapshot: Snapshot, consumed: Bool = false) throws -> JSONValue {
        guard case var .object(object) = state else { throw SafetyError.invalidResponse }
        guard case var .object(persistedSnapshot) = try json(snapshot) else { throw SafetyError.invalidResponse }
        persistedSnapshot["resolved_message_ids"] = .array([]) // transition metadata is never stored in core state
        object["snapshot"] = .object(persistedSnapshot)
        if consumed { object["consumed"] = .bool(true) }
        return .object(object)
    }
    static func updated(_ original: Snapshot, messages: [StoredMessage]? = nil, outbox: [SendRequest]? = nil,
                        groups: [MessageGroup]? = nil, refs: [OutboxReference]? = nil,
                        pending: [String]? = nil, resolved: [String] = [], deadline: Int64? = nil, traffic: TrafficState? = nil, maintenance: KeyMaintenanceState? = nil) -> Snapshot {
        Snapshot(account_id: original.account_id, username: testUsername(original.account_id), fingerprint: original.fingerprint, contacts: original.contacts,
                 outbox: outbox ?? original.outbox, messages: messages ?? original.messages,
                 groups: groups ?? original.groups, outbox_refs: refs ?? original.outbox_refs,
                 pending_group_senders: pending ?? original.pending_group_senders,
                 resolved_message_ids: resolved, next_expiry: deadline, traffic: traffic ?? original.traffic, key_maintenance: maintenance ?? original.key_maintenance)
    }
    static func changedMessage(_ original: StoredMessage, _ fields: [String: JSONValue]) throws -> StoredMessage {
        guard case var .object(value) = try json(original) else { throw SafetyError.invalidResponse }
        value.merge(fields) { _, new in new }
        return try JSONValue.object(value).decoded(StoredMessage.self)
    }

}

@MainActor struct Vault {
    private let scope: AccountStorageScope
    init(server: URL) throws { scope = try AccountStorageScope(server: server) }
    func load() throws -> StoredAccount? { Fixture.accounts[scope.backend] }
    func loadOperation() throws -> AccountOperation? { Fixture.operations[scope.backend] }
    func saveOperation(_ value: AccountOperation) throws {
        guard !Fixture.failOperationSave, !(value.completed && Fixture.failReceiptSave) else { throw SafetyError.persistence }
        try scope.validate(backend: value.backend)
        Fixture.operations[scope.backend] = try value.validated()
    }
    func clearOperation() throws {
        guard !Fixture.failClearOperation else { throw SafetyError.persistence }
        Fixture.operations[scope.backend] = nil
    }
    func deleteAccount() throws {
        precondition(Fixture.operation?.completed == true || Fixture.operation?.discardLocal == true || Fixture.saved?.identityReplaced == true, "Local account erased without durable receipt or explicit local-discard intent")
        guard !Fixture.failClearAccount else { throw SafetyError.persistence }
        Fixture.accounts[scope.backend] = nil
    }
    func save(_ value: StoredAccount) throws {
        guard !Fixture.failSave, Fixture.writes + 1 != Fixture.failAtWrite else { throw SafetyError.persistence }
        if let deadline = Fixture.delaySaveUntil {
            Fixture.delaySaveUntil = nil
            Thread.sleep(forTimeInterval: max(0, Double(deadline) - Date().timeIntervalSince1970 + 0.2))
        }
        try scope.validate(backend: value.backend)
        Fixture.accounts[scope.backend] = value; Fixture.writes += 1
    }
}
struct Configuration {
    let server: URL
    let environment: ServiceEnvironment
    @MainActor init() throws {
        server = Fixture.serverURL
        environment = server.host == "api.isyeet.io" ? .production : .staging
    }
}
struct LoginResponse { let token: String; let account_id: String; let username: String; let expires_at: Int64 }
struct Passkeys { @MainActor func credential(_ challenge: PasskeyChallenge, configuration: Configuration, registering: Bool, securityKey: Bool = false, excludingCredentialID: String? = nil) async throws -> JSONValue {
    guard Fixture.authAccountID != nil else { throw SafetyError.network }
    return .object([:])
} }
struct CoreResult { let state: JSONValue?; let data: JSONValue?; var resolved_message_ids: [String]? = nil }
enum CoreError: Error, LocalizedError { case coverClockUnavailable, coverUnavailable, rejected, verificationRequired, groupVerificationRequired, groupCapacityReached, identityChanged; var errorDescription: String? { "Synthetic core error" } }
@MainActor struct CryptoBridge {
    func expire(_ state: JSONValue) throws -> (state: JSONValue, snapshot: Snapshot) {
        let original = try Fixture.snapshot(state)
        if Fixture.staleExpiryOnce { Fixture.staleExpiryOnce = false; return (state, original) }
        let retained = original.retained(at: Int64(Date().timeIntervalSince1970))
        guard case var .object(object) = state else { throw CoreError.rejected }
        var pending = try object["pending_resolutions"]?.decoded([StoredMessage].self) ?? []
        pending = pending.filter { $0.isRetained(at: Int64(Date().timeIntervalSince1970)) }
        let warnings = try object["group_warnings"]?.decoded([String].self) ?? []
        let canResolve = Fixture.allowResolve && !(Fixture.resolutionGroup?.members.contains { warnings.contains($0.account_id) } ?? false)
        let resolved = canResolve ? pending : []
        if canResolve { pending = [] }
        object["pending_resolutions"] = pending.isEmpty ? nil : try Fixture.json(pending)
        let groups = retained.groups.isEmpty && !resolved.isEmpty ? [Fixture.resolutionGroup!]: retained.groups
        let updated = Fixture.updated(retained, messages: retained.messages + resolved, groups: groups,
                                      pending: Array(Set(pending.map(\.sender))).sorted(), resolved: resolved.map(\.id),
                                      deadline: pending.map(\.expires_at).min())
        return (try Fixture.replacing(.object(object), snapshot: updated), updated)
    }

    func call(_ operation: String, state: JSONValue? = nil, fields: [String: JSONValue] = [:]) throws -> CoreResult {
        if operation == "init" {
            guard case .string(let account_id) = fields["account_id"] else { throw CoreError.rejected }
            let snapshot = Snapshot(account_id: account_id, username: testUsername(account_id), fingerprint: String(repeating: "b", count: 64), contacts: [], outbox: [], messages: [], key_maintenance: KeyMaintenanceState(initial_upload_pending: true))
            return CoreResult(state: .object(["snapshot": try Fixture.json(snapshot), "identity": .string("new synthetic identity")]), data: nil)
        }
        guard let state else { throw CoreError.rejected }
        if operation.hasPrefix("device_authority_") { return try deviceCall(operation, state: state, fields: fields) }
        let snapshot = try Fixture.snapshot(state)
        switch operation {
        case "confirm_traffic_quiet":
            guard snapshot.traffic.enabled, Fixture.remoteCover,
                  case let .integer(serverTime) = fields["server_time"],
                  case let .integer(elapsed) = fields["elapsed_seconds"], (0...60).contains(elapsed),
                  abs(serverTime - Int64(Date().timeIntervalSince1970)) <= 60 else { throw CoreError.coverClockUnavailable }
            guard case var .object(object) = state else { throw CoreError.rejected }
            Fixture.confirmations += 1
            object["traffic_confirmation"] = .integer(Int64(Fixture.confirmations))
            return CoreResult(state: .object(object), data: try Fixture.json(snapshot))
        case "set_traffic_mode":
            guard case let .bool(enabled) = fields["enabled"] else { throw CoreError.rejected }
            if enabled { precondition(Fixture.remoteCover, "Consent enabled before server quiet") }
            var traffic = snapshot.traffic
            traffic.enabled = enabled
            let removed = enabled ? [] : traffic.cover_outbox_ids
            if !enabled { traffic.cover_outbox_ids = [] }
            let updated = Fixture.updated(snapshot, outbox: snapshot.outbox.filter { !removed.contains($0.id) }, traffic: traffic)
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: try Fixture.json(updated))
        case "create_cover":
            guard snapshot.traffic.enabled, snapshot.traffic.cover_outbox_ids.isEmpty,
                  case let .string(recipient) = fields["recipient"], snapshot.traffic.eligible_contacts.contains(recipient) else { throw CoreError.rejected }
            let outgoing = SendRequest(id: UUID().uuidString.lowercased(), recipient: recipient, envelope: "synthetic cover", expires_at: Int64(Date().timeIntervalSince1970) + 60)
            var traffic = snapshot.traffic
            traffic.cover_outbox_ids = [outgoing.id]; traffic.remaining_budget -= 1; traffic.outstanding += 1
            let updated = Fixture.updated(snapshot, outbox: snapshot.outbox + [outgoing], traffic: traffic)
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: try Fixture.json(outgoing))
        case "encrypt":
            guard Fixture.selfMessages, fields["recipient"] == .string(snapshot.account_id),
                  case .string = fields["text"] else { throw CoreError.rejected }
            let outgoing = SendRequest(id: "00000000-0000-4000-8000-000000000090", recipient: snapshot.account_id,
                                       envelope: "synthetic encrypted loopback", expires_at: Int64(Date().timeIntervalSince1970) + 60)
            let updated = Fixture.updated(snapshot, outbox: snapshot.outbox + [outgoing])
            guard case var .object(saved) = try Fixture.replacing(state, snapshot: updated) else { throw CoreError.rejected }
            saved["synthetic_loopback_text"] = fields["text"]
            return CoreResult(state: .object(saved), data: try Fixture.json(outgoing))
        case "sent":
            guard case let .string(id) = fields["id"] else { throw CoreError.rejected }
            let remaining = snapshot.outbox.filter { $0.id != id }
            let reference = snapshot.outbox_refs.first { $0.id == id }
            let messages = try snapshot.messages.map { message in
                guard reference?.message_id == message.id else { return message }
                let accepted = (message.accepted_count ?? 0) + 1
                return try Fixture.changedMessage(message, ["accepted_count": .integer(Int64(accepted)),
                    "status": .string(accepted == message.recipient_count ? "relay_accepted" : "partially_accepted")])
            }
            var traffic = snapshot.traffic; traffic.cover_outbox_ids.removeAll { $0 == id }
            let updated = Fixture.updated(snapshot, messages: messages, outbox: remaining, refs: snapshot.outbox_refs.filter { $0.id != id }, traffic: traffic)
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: nil)
        case "validate_registered_keys":
            guard case .object(let keys) = fields["keys"], case .object(let expected) = Fixture.keys(),
                  ["identity_key", "registration_id", "signed_pre_key", "kyber_pre_key"].allSatisfy({ keys[$0] == expected[$0] }) else { throw CoreError.rejected }
            return CoreResult(state: state, data: nil)
        case "confirm_initial_upload":
            let updated = Fixture.updated(snapshot, maintenance: KeyMaintenanceState())
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: try Fixture.json(updated))
        case "prepare_key_maintenance":
            let request = JSONValue.object(["operation_id": .string("00000000-0000-4000-8000-000000000123"),
                "expected_generation": .integer(0), "keys": Fixture.keys()])
            let updated = Fixture.updated(snapshot, maintenance: KeyMaintenanceState(pending: request, next_check_at: 0))
            guard case var .object(saved) = try Fixture.replacing(state, snapshot: updated) else { throw CoreError.rejected }
            saved["prepared_private_keys"] = .string("synthetic saved private material")
            return CoreResult(state: .object(saved), data: request)
        case "confirm_key_maintenance":
            guard case .object(let request) = snapshot.key_maintenance.pending,
                  case .object(let receipt) = fields["receipt"], receipt["operation_id"] == request["operation_id"],
                  receipt["generation"] == .integer(1) else { throw CoreError.rejected }
            let updated = Fixture.updated(snapshot, maintenance: KeyMaintenanceState(next_check_at: Int64(Date().timeIntervalSince1970) + 3600))
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: try Fixture.json(updated))
        case "key_upload": return CoreResult(state: state, data: Fixture.keys())
        case "add_contact":
            guard case .object(let bundle) = fields["bundle"], case .string(let account_id) = bundle["account_id"],
                  case .string(let fingerprint) = bundle["fingerprint"] else { throw CoreError.rejected }
            if snapshot.contacts.contains(where: { $0.account_id == account_id }) { return CoreResult(state: state, data: nil) }
            let updated = Snapshot(account_id: snapshot.account_id, username: testUsername(snapshot.account_id), fingerprint: snapshot.fingerprint,
                contacts: snapshot.contacts + [Contact(account_id: account_id, username: testUsername(account_id), fingerprint: fingerprint, verified: false)],
                outbox: snapshot.outbox, messages: snapshot.messages, groups: snapshot.groups, outbox_refs: snapshot.outbox_refs)
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: nil)
        case "verify_contact":
            guard case .string(let account_id) = fields["account_id"], case .string(let fingerprint) = fields["fingerprint"],
                  snapshot.contacts.contains(where: { $0.account_id == account_id && $0.fingerprint == fingerprint }) else { throw CoreError.rejected }
            let updated = Snapshot(account_id: snapshot.account_id, username: testUsername(snapshot.account_id), fingerprint: snapshot.fingerprint,
                contacts: snapshot.contacts.map { $0.account_id == account_id ? Contact(account_id: account_id, username: testUsername(account_id), fingerprint: fingerprint, verified: true) : $0 },
                outbox: snapshot.outbox, messages: snapshot.messages, groups: snapshot.groups, outbox_refs: snapshot.outbox_refs)
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: nil)
        case "block_groups_for_contact":
            guard case let .string(account_id) = fields["account_id"], case var .object(object) = state else { throw CoreError.rejected }
            if let expected = fields["fingerprint"], !snapshot.contacts.contains(where: { $0.account_id == account_id && .string($0.fingerprint) == expected }) {
                return CoreResult(state: state, data: nil)
            }
            let warnings = try object["group_warnings"]?.decoded([String].self) ?? []
            object["group_warnings"] = try Fixture.json(Array(Set(warnings + [account_id])).sorted())
            let groups = snapshot.groups.map { group in
                MessageGroup(id: group.id, title: group.title, members: group.members,
                             blocked: group.blocked || group.members.contains { $0.account_id == account_id })
            }
            let blocked = Set(groups.filter(\.blocked).map(\.id))
            let removed = Set(snapshot.outbox_refs.filter { blocked.contains($0.group_id) }.map(\.id))
            let updated = Fixture.updated(snapshot, outbox: snapshot.outbox.filter { !removed.contains($0.id) }, groups: groups,
                                          refs: snapshot.outbox_refs.filter { !removed.contains($0.id) })
            return CoreResult(state: try Fixture.replacing(.object(object), snapshot: updated), data: nil)
        case "create_group":
            guard case let .string(title) = fields["title"], case let .array(account_ids) = fields["members"] else { throw CoreError.rejected }
            let peers = try account_ids.map { value -> MessageGroup.Member in
                guard case let .string(account_id) = value, let contact = snapshot.contacts.first(where: { $0.account_id == account_id && $0.verified }) else { throw CoreError.rejected }
                return .init(account_id: account_id, fingerprint: contact.fingerprint)
            }
            let group = MessageGroup(id: String(repeating: "1", count: 64), title: title,
                                     members: [.init(account_id: snapshot.account_id, fingerprint: snapshot.fingerprint)] + peers, blocked: false)
            let updated = Fixture.updated(snapshot, groups: snapshot.groups + [group])
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: try Fixture.json(group))
        case "encrypt_group":
            guard case let .string(id) = fields["group_id"], case let .string(text) = fields["text"],
                  let group = snapshot.groups.first(where: { $0.id == id && !$0.blocked }) else { throw CoreError.rejected }
            let expiry = Int64(Date().timeIntervalSince1970) + 604_800
            let recipients = group.members.filter { $0.account_id != snapshot.account_id }
            let message = StoredMessage(id: "00000000-0000-4000-8000-000000000399", sender: snapshot.account_id,
                                        recipient: snapshot.account_id, text: text, security_alert: nil, duplicate: false, expires_at: expiry,
                                        group_id: group.id, sent_at: expiry - 604_800, sender_fingerprint: snapshot.fingerprint,
                                        status: "queued", accepted_count: 0, recipient_count: recipients.count)
            let envelopes = recipients.enumerated().map { index, member in
                SendRequest(id: String(format: "00000000-0000-4000-8000-%012d", 400 + index), recipient: member.account_id,
                            envelope: "synthetic group leg", expires_at: expiry)
            }
            let refs = envelopes.map { OutboxReference(id: $0.id, group_id: group.id, message_id: message.id, recipient: $0.recipient) }
            let updated = Fixture.updated(snapshot, messages: snapshot.messages + [message], outbox: snapshot.outbox + envelopes,
                                          refs: snapshot.outbox_refs + refs)
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: try Fixture.json(envelopes))
        case "remove_contact":
            guard !Fixture.rejectReplacement, case let .string(account_id) = fields["account_id"],
                  case let .string(old) = fields["previous_fingerprint"],
                  snapshot.contacts.contains(where: { $0.account_id == account_id && $0.fingerprint == old }) else { throw CoreError.rejected }
            let groups = snapshot.groups.map { group in
                MessageGroup(id: group.id, title: group.title, members: group.members,
                    blocked: group.blocked || group.members.contains { $0.account_id == account_id })
            }
            let blocked = Set(groups.filter(\.blocked).map(\.id))
            let cancelled = Set(snapshot.outbox_refs.filter { blocked.contains($0.group_id) }.map(\.id))
            let updated = Snapshot(account_id: snapshot.account_id, username: testUsername(snapshot.account_id), fingerprint: snapshot.fingerprint,
                contacts: snapshot.contacts.filter { $0.account_id != account_id },
                outbox: snapshot.outbox.filter { $0.recipient != account_id && !cancelled.contains($0.id) },
                messages: snapshot.messages.filter { $0.group_id != nil || ($0.sender != account_id && $0.recipient != account_id) },
                groups: groups, outbox_refs: snapshot.outbox_refs.filter { !cancelled.contains($0.id) })
            return CoreResult(state: try Fixture.replacing(state, snapshot: updated), data: nil)
        case "decrypt":
            if let arrival = Fixture.directArrival {
                let incoming = try fields["message"]!.decoded(QueuedMessage.self)
                precondition(incoming.id == arrival.id && incoming.sender == arrival.sender)
                let updated = Fixture.updated(snapshot, messages: snapshot.messages + [arrival])
                return CoreResult(state: try Fixture.replacing(state, snapshot: updated, consumed: true), data: try Fixture.json(arrival))
            }
            if Fixture.coverArrives {
                let incoming = try fields["message"]!.decoded(QueuedMessage.self)
                let cover = StoredMessage(id: incoming.id, sender: incoming.sender, recipient: snapshot.account_id, text: nil,
                                          security_alert: nil, duplicate: false, expires_at: Int64(Date().timeIntervalSince1970) + 60, cover: true)
                return CoreResult(state: try Fixture.replacing(state, snapshot: snapshot, consumed: true), data: try Fixture.json(cover))
            }
            if let pending = Fixture.deferredArrival {
                guard case var .object(object) = state else { throw CoreError.rejected }
                object["pending_resolutions"] = try Fixture.json([pending])
                let updated = Fixture.updated(snapshot, pending: [pending.sender], deadline: pending.expires_at)
                let deferred = StoredMessage(id: Fixture.incoming[0].id, sender: pending.sender, recipient: snapshot.account_id,
                                             text: nil, security_alert: nil, duplicate: false, expires_at: pending.expires_at, deferred: true)
                return CoreResult(state: try Fixture.replacing(.object(object), snapshot: updated, consumed: true), data: try Fixture.json(deferred))
            }
            if Fixture.selfMessages {
                guard case let .object(saved) = state, case let .string(text) = saved["synthetic_loopback_text"] else { throw CoreError.rejected }
                if snapshot.messages.contains(where: { $0.id == Fixture.incoming[0].id }) {
                    let duplicate = StoredMessage(id: Fixture.incoming[0].id, sender: snapshot.account_id, recipient: snapshot.account_id,
                                                  text: nil, security_alert: nil, duplicate: true, expires_at: 0)
                    return CoreResult(state: state, data: try Fixture.json(duplicate))
                }
                let message = StoredMessage(id: Fixture.incoming[0].id, sender: snapshot.account_id, recipient: snapshot.account_id,
                                            text: Fixture.rejectSelfReturn ? nil : text,
                                            security_alert: Fixture.rejectSelfReturn ? "synthetic rejection" : nil,
                                            duplicate: false, expires_at: Int64(Date().timeIntervalSince1970) + 60)
                let updated = Snapshot(account_id: snapshot.account_id, username: testUsername(snapshot.account_id), fingerprint: snapshot.fingerprint, contacts: snapshot.contacts,
                                       outbox: snapshot.outbox, messages: snapshot.messages + [message])
                return CoreResult(state: try Fixture.replacing(state, snapshot: updated, consumed: true), data: try Fixture.json(message))
            }
            if Fixture.identityChangedOnDecrypt {
                guard snapshot.contacts.contains(where: { $0.account_id == "0beaac69-d53e-48d2-b5aa-dd405b7f414d" && $0.fingerprint == String(repeating: "b", count: 64) }) else { throw CoreError.identityChanged }
                let message = StoredMessage(id: Fixture.incoming[0].id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296",
                                            text: "new synthetic identity", security_alert: nil, duplicate: false,
                                            expires_at: Int64(Date().timeIntervalSince1970) + 60)
                let updated = Snapshot(account_id: snapshot.account_id, username: testUsername(snapshot.account_id), fingerprint: snapshot.fingerprint, contacts: snapshot.contacts,
                                       outbox: snapshot.outbox, messages: snapshot.messages + [message])
                return CoreResult(state: try Fixture.replacing(state, snapshot: updated, consumed: true), data: try Fixture.json(message))
            }
            let message = StoredMessage(id: Fixture.incoming[0].id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296",
                                        text: nil, security_alert: nil, duplicate: false, expires_at: 1, expired: true)
            return CoreResult(state: try Fixture.replacing(state, snapshot: snapshot, consumed: true), data: try Fixture.json(message))
        default: throw CoreError.rejected
        }
    }
}
@MainActor struct API {
    static let inboxPageSize = 50
    let base: URL
    private func challenge() -> PasskeyChallenge {
        PasskeyChallenge(challenge_id: UUID().uuidString.lowercased(), account_id: Fixture.authAccountID, username: Fixture.authAccountID.map(testUsername),
            public_key: PasskeyOptions(challenge: "AA", rp: nil, rpId: nil, user: nil, excludeCredentials: nil, allowCredentials: nil, pubKeyCredParams: nil))
    }
    func registrationStart(username: String) async throws -> PasskeyChallenge { challenge() }
    func loginStart() async throws -> PasskeyChallenge { challenge() }
    func loginFinish(challengeID: String, credential: JSONValue, registering: Bool) async throws -> LoginResponse {
        Fixture.loginCalls += 1
        guard let account_id = Fixture.authAccountID else { throw SafetyError.network }
        return LoginResponse(token: "renewed synthetic", account_id: account_id, username: testUsername(account_id), expires_at: Int64.max)
    }
    func reauthenticationStart(token: String, purpose: String) async throws -> PasskeyChallenge {
        if purpose == "device_manage" { Fixture.deviceProofs += 1 }
        return challenge()
    }
    func reauthenticationFinish(token: String, challengeID: String, credential: JSONValue) async throws -> PasskeyAction {
        PasskeyAction(action_token: "synthetic-action-proof", expires_at: Int64.max)
    }
    func passkeys(token: String) async throws -> [RegisteredPasskey] { [] }
    func deviceAuthority(token: String) async throws -> DeviceAuthorityResponse {
        Fixture.deviceAuthorityCalls += 1
        guard Fixture.deviceNetworkEnabled else { throw SafetyError.network }
        return .init(authority: Fixture.deviceRemoteAuthority, server_time: Int64(Date().timeIntervalSince1970), messaging_available: false)
    }
    func changeDeviceAuthority(_ change: JSONValue, token: String, actionToken: String) async throws -> DeviceAuthorityReceipt {
        Fixture.deviceAuthorityCalls += 1
        guard Fixture.deviceNetworkEnabled else { throw SafetyError.network }
        Fixture.deviceMutationCalls.append(change)
        guard !Fixture.deviceRejectMutation else { throw SafetyError.network }
        guard case .object(let signed) = change, case .object(let body) = signed["change"],
              let roster = body["roster"], case .string(let operationID) = body["operation_id"] else { throw SafetyError.invalidResponse }
        Fixture.deviceRemoteAuthority = roster
        if Fixture.deviceLoseReceipt { throw SafetyError.network }
        return .init(operation_id: operationID, roster_version: 1, roster_hash: String(repeating: "a", count: 64), messaging_available: false)
    }
    func addPasskeyStart(token: String, actionToken: String, label: String) async throws -> PasskeyChallenge { challenge() }
    func addPasskeyFinish(token: String, challengeID: String, credential: JSONValue) async throws {}
    func removePasskey(id: String, token: String, actionToken: String) async throws {}
    func lookup(username: String, token: String) async throws -> DirectoryAccount {
        let pairs = ["me_test": "81d1a713-5b97-4257-bfb4-f094a2004296", "alice": "0beaac69-d53e-48d2-b5aa-dd405b7f414d", "bob": "300db02d-b75a-4922-8759-f08a0efa5a40", "carol": "c36e0493-49f8-4439-aa4c-2aa333bf235f", "dave": "781e65af-8b81-4d42-9fef-a6bc1253f62f", "outsider": "9fa56b84-e436-4423-8452-b98816524ec5", "other": "18ae18f2-64c2-4442-a0aa-fe2ef8d2d130", "elsewhere": "ee9c5bcd-53b5-4939-b07a-8e021c7b6cfc", "a_test": "75f4499b-5920-4d38-b057-e967e297590a"]
        guard let id = pairs[username] else { throw SafetyError.invalidUsername }
        return DirectoryAccount(account_id: id, username: username)
    }
    func requireUnregisteredIdentity(token: String) async throws {
        if Fixture.registrationExists { throw SafetyError.identityAlreadyRegistered }
    }
    func accountState(token: String, account_id: String) async throws -> AccountStateResponse? {
        guard !Fixture.remoteAbsent else { return nil }
        return AccountStateResponse(account_id: account_id, generation: Fixture.remoteGeneration,
            identity_fingerprint: Fixture.remoteFingerprint, server_time: Fixture.operationServerTime ?? Int64(Date().timeIntervalSince1970))
    }
    func accountState(actionToken: String, account_id: String) async throws -> AccountStateResponse? {
        guard !Fixture.remoteAbsent else { return nil }
        return AccountStateResponse(account_id: account_id, generation: Fixture.remoteGeneration,
            identity_fingerprint: Fixture.remoteFingerprint, server_time: Fixture.operationServerTime ?? Int64(Date().timeIntervalSince1970))
    }
    func performAccountOperation(_ operation: AccountOperation) async throws {
        precondition(Fixture.operation == operation, "Destructive request before exact journal save")
        if operation.kind == .reenroll { precondition(operation.preparedCore != nil && operation.preparedKeys != nil) }
        Fixture.operationRequests.append(operation)
        if Fixture.holdAccountOperation { await withCheckedContinuation { Fixture.heldAccountOperation = $0 } }
        if Fixture.failRemoteOperation { throw SafetyError.network }
        if Fixture.conflictOperation { throw SafetyError.accountOperationConflict }
    }
    func keyMaintenanceInventory(token: String) async throws -> JSONValue {
        Fixture.maintenanceReads += 1
        return .object(["generation": .integer(0), "keys": Fixture.keys(remaining: true)])
    }
    func maintainKeys(_ pending: JSONValue, token: String) async throws -> JSONValue {
        let durable = try Fixture.snapshot(Fixture.saved!.core)
        precondition(durable.key_maintenance.pending == pending, "Maintenance PUT before private proposal save")
        Fixture.maintenanceRequests.append(pending)
        if Fixture.holdMaintenance { await withCheckedContinuation { Fixture.heldMaintenance = $0 } }
        if Fixture.failMaintenance { throw SafetyError.network }
        guard case .object(let request) = pending else { throw SafetyError.invalidResponse }
        return .object(["operation_id": Fixture.mismatchMaintenanceReceipt ? .string(UUID().uuidString.lowercased()) : request["operation_id"]!, "generation": .integer(1)])
    }
    func ownKeys(token: String) async throws -> JSONValue? {
        if Fixture.failOwnKeys { throw SafetyError.network }
        if Fixture.missingOwnKeys { return nil }
        guard case var .object(keys) = Fixture.keys(Fixture.mismatchOwnKeys ? "superseding key" : "synthetic-new-key", remaining: true) else { throw SafetyError.invalidResponse }
        if Fixture.mismatchSignedKeys { keys["signed_pre_key"] = .string("unknown signed key") }
        return .object(keys)
    }
    func claim(account_id: String, token: String) async throws -> JSONValue {
        Fixture.keyClaims += 1
        if Fixture.holdClaim { await withCheckedContinuation { Fixture.heldClaim = $0 } }
        if Fixture.claimError { throw SafetyError.network }
        return Fixture.claimBundle ?? .object(["account_id": .string(account_id), "username": .string(testUsername(account_id)), "fingerprint": .string(String(repeating: "b", count: 64))])
    }
    func upload(keys: JSONValue, token: String) async throws { Fixture.uploads += 1; if Fixture.failUpload { throw SafetyError.network } }
    func syncContacts(account_ids: [String], token: String) async throws {
        Fixture.permissionUpdates += 1
        if Fixture.holdPermissions { await withCheckedContinuation { Fixture.heldPermissions = $0 } }
        if Fixture.failPermissions { throw SafetyError.network }
    }
    func updatePushToken(_ deviceToken: String?, token: String) async throws { Fixture.pushUpdates += 1 }
    func trafficMode(token: String, allowLegacy: Bool) async throws -> TrafficModeResponse? {
        Fixture.policyReads += 1
        if Fixture.holdMode { Fixture.holdMode = false; await withCheckedContinuation { Fixture.heldMode = $0 } }
        if Fixture.failMode { throw SafetyError.network }
        return TrafficModeResponse(cover: Fixture.remoteCover, notifications_resume_at: Fixture.remoteCover ? nil : 0, server_time: Int64(Date().timeIntervalSince1970) + Fixture.serverTimeOffset)
    }
    func setTrafficMode(cover: Bool, token: String) async throws -> TrafficModeResponse {
        Fixture.modeCalls.append(cover)
        if !cover {
            let saved = try Fixture.snapshot(Fixture.saved!.core)
            precondition(!saved.traffic.enabled, "Remote alerts enabled before durable consent revocation")
        }
        if Fixture.failMode { throw SafetyError.network }
        Fixture.remoteCover = cover
        return TrafficModeResponse(cover: cover, notifications_resume_at: cover ? nil : Int64(Date().timeIntervalSince1970) + 420, server_time: Int64(Date().timeIntervalSince1970) + Fixture.serverTimeOffset)
    }
    func send(_ value: SendRequest, token: String) async throws {
        let saved = try Fixture.snapshot(Fixture.saved!.core)
        precondition(saved.outbox.contains { $0.id == value.id }, "Send before durable outbox")
        if saved.traffic.enabled {
            guard case let .object(object) = Fixture.saved!.core else { throw SafetyError.persistence }
            precondition(object["traffic_confirmation"] == .integer(Int64(Fixture.confirmations)), "Send before current slot confirmation was saved")
        }
        Fixture.sent.append(value.id)
        if Fixture.holdSend { Fixture.holdSend = false; await withCheckedContinuation { Fixture.heldSend = $0 } }
        if Fixture.failSend || Fixture.failedRecipients.contains(value.recipient) { throw SafetyError.network }
        if Fixture.selfMessages {
            Fixture.incoming = [QueuedMessage(id: value.id, sender: value.recipient, envelope: value.envelope,
                                              created_at: Int64(Date().timeIntervalSince1970))]
        }
    }
    func inbox(token: String) async throws -> [QueuedMessage] {
        if Fixture.holdInbox { Fixture.holdInbox = false; await withCheckedContinuation { Fixture.heldInbox = $0 } }
        return Fixture.incoming
    }
    func acknowledge(_ id: String, token: String) async throws {
        guard case let .object(state) = Fixture.saved?.core, state["consumed"] == .bool(true) else {
            fatalError("ACK before durable incoming state")
        }
        Fixture.acknowledgements += 1
    }
}

@main struct LifecycleChecks {
    @MainActor static func main() async throws {
        func now() -> Int64 { Int64(Date().timeIntervalSince1970) }
        func message(_ index: Int, expiry: Int64) -> StoredMessage {
            StoredMessage(id: String(format: "00000000-0000-4000-8000-%012d", index), sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                          recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", text: "synthetic", security_alert: nil, duplicate: false, expires_at: expiry)
        }
        func envelope(_ index: Int, expiry: Int64) -> SendRequest {
            SendRequest(id: String(format: "00000000-0000-4000-8000-%012d", index), recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
                        envelope: "synthetic ciphertext", expires_at: expiry)
        }
        func waitUntil(_ condition: () -> Bool) async throws {
            for _ in 0..<100 { if condition() { return }; try await Task.sleep(for: .milliseconds(20)) }
            preconditionFailure("Synthetic request never suspended")
        }
        func waitPast(_ deadline: Int64) async throws {
            try await Task.sleep(for: .seconds(max(0.1, Double(deadline) - Date().timeIntervalSince1970 + 0.2)))
        }

        #if DEBUG && ISYEET_DEVICE_AUTHORIZATION_EXPERIMENT
        try await runDeviceAuthorizationChecks()
        #else
        // The ordinary app cannot reach experimental authorization even when
        // its methods are invoked directly, bypassing the hidden Settings link.
        try Fixture.reset([], sessionValid: true)
        let gatedDevices = AppModel()
        precondition(!gatedDevices.experimentalDeviceAuthorizationAvailable)
        await gatedDevices.refreshMessagingDevices()
        await gatedDevices.prepareMessagingDeviceAuthority()
        await gatedDevices.inspectDevicePairing("ISYEET-LINK-1:e30")
        await gatedDevices.resumeDeviceAuthorization()
        await gatedDevices.approveReviewedDevice()
        let syntheticDevice = DeviceRosterMember(certificate: .init(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", root_epoch: "synthetic", device_id: 2,
                identity_key: "synthetic", registration_id: 1, label: "Synthetic", request_hash: "synthetic"), signature: "synthetic")
        await gatedDevices.revokeMessagingDevice(syntheticDevice)
        precondition(Fixture.deviceAuthorityCalls == 0 && gatedDevices.deviceAuthority == nil && gatedDevices.devicePairingReview == nil)
        print("PASS disabled device authorization cannot access experimental endpoints or create a proposal")

        // Loading never publishes an expired record; refresh still cleans up
        // with an expired login session and without any network call.
        let deadline = now() + 2
        try Fixture.reset([message(1, expiry: now() - 1), message(2, expiry: deadline)], outbox: [envelope(2, expiry: deadline)])
        let offline = AppModel()
        precondition(offline.snapshot?.messages.count == 1 && offline.needsAuthentication && Fixture.writes == 1)
        try await waitPast(deadline)
        await offline.refresh(quiet: true)
        precondition(offline.snapshot?.messages.isEmpty == true && offline.unreadCount == 0 && Fixture.sent.isEmpty)
        let offlineSaved = try Fixture.snapshot(Fixture.saved!.core)
        precondition(offlineSaved.outbox.isEmpty)
        print("PASS offline and expired-session cleanup before publication")

        // The core/Swift second boundary requires another core transition,
        // not a display-only filter that strands expired saved plaintext.
        try Fixture.reset([message(3, expiry: now())])
        Fixture.staleExpiryOnce = true
        let boundary = AppModel()
        precondition(boundary.fatalError == nil && boundary.snapshot?.messages.isEmpty == true)
        let boundarySaved = try Fixture.snapshot(Fixture.saved!.core)
        precondition(boundarySaved.messages.isEmpty)
        print("PASS core/Swift deadline crossing persists a pruned state")

        let storageDeadline = now() + 1
        try Fixture.reset([message(30, expiry: storageDeadline)])
        Fixture.delaySaveUntil = storageDeadline
        let slowStorage = AppModel()
        let storageSaved = try Fixture.snapshot(Fixture.saved!.core)
        precondition(Fixture.writes == 2 && slowStorage.snapshot?.messages.isEmpty == true && storageSaved.messages.isEmpty)
        print("PASS slow storage deadline crossing is re-pruned before publication")

        // A slow first delivery cannot delay active expiry or send a later
        // queued envelope whose original deadline has passed during the await.
        let pendingDeadline = now() + 2
        try Fixture.reset([message(4, expiry: pendingDeadline)],
                          outbox: [envelope(10, expiry: now() + 60), envelope(11, expiry: pendingDeadline)], sessionValid: true)
        Fixture.holdSend = true
        let pending = AppModel(); pending.setAppActive(true)
        let delivery = Task { await pending.refresh(quiet: true) }
        try await waitUntil { Fixture.heldSend != nil }
        try await waitPast(pendingDeadline)
        precondition(pending.busy && pending.snapshot?.messages.isEmpty == true && pending.unreadCount == 0)
        precondition(pending.snapshot?.outbox.count == 1)
        Fixture.heldSend?.resume(); Fixture.heldSend = nil
        await delivery.value
        precondition(Fixture.sent.count == 1 && pending.snapshot?.outbox.isEmpty == true)
        pending.setAppActive(false)
        print("PASS active deadline cleanup during I/O and no expired retry")

        // A suspended continuation cannot republish after a timer's failed
        // secure save, even if storage recovers before the network returns.
        let failureDeadline = now() + 2
        try Fixture.reset([message(5, expiry: failureDeadline)], sessionValid: true)
        Fixture.holdClaim = true
        let failed = AppModel(); failed.setAppActive(true)
        let lookup = Task { await failed.addContact("bob") }
        try await waitUntil { Fixture.heldClaim != nil }
        Fixture.failSave = true
        try await waitPast(failureDeadline)
        precondition(failed.fatalError != nil && failed.snapshot == nil)
        Fixture.failSave = false
        Fixture.heldClaim?.resume(); Fixture.heldClaim = nil
        await lookup.value
        precondition(failed.fatalError != nil && failed.snapshot == nil)
        failed.retryLoad()
        precondition(failed.fatalError == nil && failed.snapshot?.messages.isEmpty == true)
        failed.setAppActive(false)
        print("PASS storage failure hides plaintext until explicit recovery")

        // The expired arrival consumes ratchet/dedupe state before its ACK;
        // it creates no message row, security alert or unread indicator.
        try Fixture.reset([], sessionValid: true)
        Fixture.incoming = [QueuedMessage(id: message(20, expiry: 1).id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", envelope: "synthetic", created_at: 1)]
        let receiver = AppModel()
        await receiver.refresh()
        precondition(Fixture.acknowledgements == 1 && receiver.snapshot?.messages.isEmpty == true)
        precondition(receiver.unreadCount == 0 && receiver.alert == nil && !receiver.showsNewMessageIndicator)
        print("PASS silent expired incoming storage precedes ACK")

        // The first save may commit an advanced ratchet before expiry is
        // detected. If cleanup's second save fails, the old in-memory state
        // must never be used for another send or incoming acknowledgment.
        let partialDeadline = now() + 2
        try Fixture.reset([message(40, expiry: partialDeadline)], sessionValid: true)
        Fixture.incoming = [QueuedMessage(id: message(41, expiry: 1).id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", envelope: "synthetic", created_at: 1)]
        let partial = AppModel()
        Fixture.delaySaveUntil = partialDeadline
        Fixture.failAtWrite = Fixture.writes + 2
        await partial.refresh()
        precondition(partial.snapshot == nil && partial.fatalError != nil && Fixture.acknowledgements == 0)
        if case let .object(state) = Fixture.saved?.core { precondition(state["consumed"] == .bool(true)) }
        else { preconditionFailure("Successful first write lost") }
        let allowedSend = await partial.send(text: "synthetic", recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d")
        await partial.refresh()
        precondition(!allowedSend && Fixture.sent.isEmpty && Fixture.acknowledgements == 0 && partial.snapshot == nil)
        Fixture.failAtWrite = nil
        partial.retryLoad()
        precondition(partial.fatalError == nil && partial.snapshot?.messages.isEmpty == true)
        print("PASS second-save failure blocks stale ratchet use until reload")
        if case let .object(state) = Fixture.saved?.core {
            precondition(state["identity"] == .string("unchanged synthetic key marker"))
        } else { preconditionFailure("Identity marker lost") }

        let alice = Contact(account_id: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", username: testUsername("0beaac69-d53e-48d2-b5aa-dd405b7f414d"), fingerprint: String(repeating: "a", count: 64), verified: true)
        let bob = Contact(account_id: "300db02d-b75a-4922-8759-f08a0efa5a40", username: testUsername("300db02d-b75a-4922-8759-f08a0efa5a40"), fingerprint: String(repeating: "c", count: 64), verified: true)
        // Management/composer/settings presentations can cover a chat whose
        // navigation identity remains selected. Incoming text is durably unread
        // until the actual conversation is visible again, not merely selected.
        for (index, sheet) in ["contact-details", "compose", "add-contact", "new-group", "appearance"].enumerated() {
            try Fixture.reset([], sessionValid: true, contacts: [alice, bob])
            let coveredChat = AppModel(); coveredChat.setAppActive(true)
            coveredChat.conversationDidAppear(alice.account_id)
            coveredChat.setPresentationCovered(sheet, covered: true)
            let arrival = message(800 + index, expiry: now() + 60)
            Fixture.directArrival = arrival
            Fixture.incoming = [QueuedMessage(id: arrival.id, sender: alice.account_id, envelope: "synthetic sheet arrival", created_at: now())]
            await coveredChat.refresh(quiet: true)
            precondition(Fixture.acknowledgements == 1 && coveredChat.unreadCounts == [alice.account_id: 1])
            precondition(Fixture.saved?.unreadMessageIDs == [arrival.id] && coveredChat.showsNewMessageIndicator)
            let navigation = coveredChat.inboxNavigationSequence
            coveredChat.showInbox()
            precondition(coveredChat.inboxNavigationSequence == navigation + 1)
            coveredChat.setPresentationCovered(sheet, covered: false)
            coveredChat.conversationDidDisappear(alice.account_id)
            coveredChat.updateReadVisibility()
            precondition(coveredChat.unreadCount == 1 && Fixture.saved?.unreadMessageIDs == [arrival.id], "Returning to inbox must not read the covered chat")
            coveredChat.conversationDidAppear(alice.account_id)
            precondition(coveredChat.unreadCount == 0 && Fixture.saved?.unreadMessageIDs.isEmpty == true)
            coveredChat.setAppActive(false)
            print("PASS \(sheet) arrival stays unread through inbox return until conversation opens")
        }

        // Dismissing one of two overlapping presentation owners must not make
        // the underlying conversation readable while the other still covers it.
        let nestedArrival = message(810, expiry: now() + 60)
        try Fixture.reset([nestedArrival], contacts: [alice])
        let nestedSheets = AppModel(); nestedSheets.setAppActive(true)
        nestedSheets.setPresentationCovered("contact-details", covered: true)
        nestedSheets.setPresentationCovered("compose", covered: true)
        nestedSheets.conversationDidAppear(alice.account_id)
        precondition(nestedSheets.unreadCount == 1)
        nestedSheets.setPresentationCovered("contact-details", covered: false)
        precondition(nestedSheets.unreadCount == 1 && Fixture.saved?.unreadMessageIDs == [nestedArrival.id])
        nestedSheets.setPresentationCovered("compose", covered: false)
        precondition(nestedSheets.unreadCount == 0 && Fixture.saved?.unreadMessageIDs.isEmpty == true)
        nestedSheets.setAppActive(false)
        print("PASS nested sheet dismissal preserves unread until the last covering presentation closes")

        // Inbox previews derive from current retained history. A management
        // sheet neither marks the underlying chat read nor freezes expired text.
        let previewDeadline = now() + 2
        let olderPreview = try Fixture.changedMessage(message(820, expiry: now() + 60), ["text": .string("Earlier retained note")])
        let newestPreview = try Fixture.changedMessage(message(821, expiry: previewDeadline), ["text": .string("Short-lived note")])
        try Fixture.reset([olderPreview, newestPreview], contacts: [alice])
        let previewExpiry = AppModel(); previewExpiry.setAppActive(true)
        previewExpiry.setPresentationCovered("contact-management:synthetic", covered: true)
        previewExpiry.conversationDidAppear(alice.account_id)
        let initialPreview = previewExpiry.snapshot?.conversations(unreadCounts: previewExpiry.unreadCounts, at: now()).first { $0.id == alice.account_id }
        precondition(initialPreview?.preview == newestPreview.text && initialPreview?.latestMessageID == newestPreview.id && initialPreview?.unreadCount == 2)
        try await waitPast(previewDeadline)
        let retainedPreview = previewExpiry.snapshot?.conversations(unreadCounts: previewExpiry.unreadCounts, at: now()).first { $0.id == alice.account_id }
        precondition(retainedPreview?.preview == olderPreview.text && retainedPreview?.latestMessageID == olderPreview.id && retainedPreview?.unreadCount == 1)
        precondition(previewExpiry.snapshot?.message(id: newestPreview.id, at: now()) == nil)
        let savedPreview = try Fixture.snapshot(Fixture.saved!.core)
        precondition(savedPreview.messages.map(\.id) == [olderPreview.id])
        precondition(Fixture.saved?.unreadMessageIDs == [olderPreview.id])
        previewExpiry.showInbox()
        previewExpiry.setPresentationCovered("contact-management:synthetic", covered: false)
        precondition(previewExpiry.unreadCount == 1)
        previewExpiry.setAppActive(false)
        print("PASS inbox preview falls back after durable expiry without marking covered history read")

        let removal = ContactRemoval(contact: alice)
        let newFingerprint = String(repeating: "b", count: 64)
        let retainedBob = StoredMessage(id: message(51, expiry: now() + 60).id, sender: bob.account_id, recipient: "81d1a713-5b97-4257-bfb4-f094a2004296",
            text: "other contact", security_alert: nil, duplicate: false, expires_at: now() + 60)
        let retainedBobOutbox = SendRequest(id: envelope(53, expiry: now() + 60).id, recipient: bob.account_id,
            envelope: "other unchanged ciphertext", expires_at: now() + 60)
        try Fixture.reset([message(50, expiry: now() + 60), retainedBob],
            outbox: [envelope(52, expiry: now() + 60), retainedBobOutbox], sessionValid: true, contacts: [alice, bob])
        Fixture.saved?.contactIdentityChanges = [alice.account_id]
        let removing = AppModel()
        removing.setPresentationCovered("contact-remove", covered: true)
        let removed = await removing.removeContact(removal)
        precondition(removed == .removed && Fixture.permissionUpdates == 1 && Fixture.sent.isEmpty)
        let removedSaved = try Fixture.snapshot(Fixture.saved!.core)
        precondition(removedSaved.contacts == [bob] && removedSaved.messages == [retainedBob])
        precondition(removedSaved.outbox.map(\.id) == [retainedBobOutbox.id] && removing.unreadCounts == [bob.account_id: 1])
        let stale = await removing.removeContact(removal)
        if case .failed = stale {} else { preconditionFailure("Stale removal accepted") }
        precondition(Fixture.permissionUpdates == 1)
        print("PASS removal commits only target cleanup and rejects stale consent")

        for failure in ["core", "save"] {
            try Fixture.reset([message(60, expiry: now() + 60)], outbox: [envelope(61, expiry: now() + 60)], sessionValid: true, contacts: [alice])
            let unchanged = AppModel(); let before = Fixture.saved
            if failure == "core" { Fixture.rejectReplacement = true }
            if failure == "save" { Fixture.failSave = true }
            let outcome = await unchanged.removeContact(removal)
            if case .failed = outcome {} else { preconditionFailure("Failed removal reported committed") }
            precondition(Fixture.saved == before && unchanged.snapshot?.contacts.first == alice && Fixture.permissionUpdates == 0)
        }
        print("PASS rejected core/save failure leaves trust and history intact")

        try Fixture.reset([message(62, expiry: now() + 60)], sessionValid: true, contacts: [alice])
        let pendingPermission = AppModel(); Fixture.failPermissions = true
        let committed = await pendingPermission.removeContact(removal)
        precondition(committed == .removedPendingSynchronization && pendingPermission.snapshot?.contacts.isEmpty == true)
        let removedHistory = try Fixture.snapshot(Fixture.saved!.core)
        precondition(removedHistory.messages.isEmpty)
        print("PASS permission failure reports committed removal with retryable permission sync")

        let removalDeadline = now() + 2
        let expiredBob = StoredMessage(id: message(70, expiry: removalDeadline).id, sender: bob.account_id, recipient: "81d1a713-5b97-4257-bfb4-f094a2004296",
            text: "expires during permission update", security_alert: nil, duplicate: false, expires_at: removalDeadline)
        try Fixture.reset([message(71, expiry: now() + 60), expiredBob], sessionValid: true, contacts: [alice, bob])
        Fixture.holdPermissions = true
        let concurrent = AppModel(); concurrent.setAppActive(true); concurrent.setPresentationCovered("contact-remove", covered: true)
        let removingTask = Task { await concurrent.removeContact(removal) }
        try await waitUntil { Fixture.heldPermissions != nil }; try await waitPast(removalDeadline)
        precondition(concurrent.snapshot?.messages.isEmpty == true)
        Fixture.heldPermissions?.resume(); Fixture.heldPermissions = nil
        let concurrentResult = await removingTask.value
        precondition(concurrentResult == .removed && concurrent.snapshot?.messages.isEmpty == true)
        concurrent.setAppActive(false)
        print("PASS permission await cannot resurrect expired unrelated messages after removal")

        try Fixture.reset([], sessionValid: true, contacts: [alice])
        Fixture.identityChangedOnDecrypt = true
        Fixture.incoming = [QueuedMessage(id: message(80, expiry: 1).id, sender: alice.account_id, envelope: "same new-identity ciphertext", created_at: 1)]
        let blocked = AppModel(); Fixture.failSave = true
        await blocked.refresh()
        precondition(blocked.fatalError != nil && blocked.snapshot == nil && Fixture.acknowledgements == 0)
        Fixture.failSave = false; blocked.retryLoad()
        precondition(blocked.pendingIdentityChanges == [alice.account_id] && Fixture.saved?.contactIdentityChanges == [alice.account_id])
        let relaunched = blocked // Same instance must preserve then transactionally clear observed warning.
        let blockedSend = await relaunched.send(text: "synthetic", recipient: alice.account_id)
        precondition(!blockedSend && Fixture.sent.isEmpty)
        let removedChanged = await relaunched.removeContact(removal)
        precondition(removedChanged == .removed && relaunched.snapshot?.contacts.isEmpty == true)
        Fixture.incoming = []
        await relaunched.addContact(alice.username)
        precondition(relaunched.snapshot?.contacts.first?.verified == false)
        await relaunched.verifyContact(account_id: alice.account_id, fingerprint: newFingerprint)
        Fixture.incoming = [QueuedMessage(id: message(80, expiry: 1).id, sender: alice.account_id, envelope: "same new-identity ciphertext", created_at: 1)]
        await relaunched.refresh()
        precondition(Fixture.acknowledgements == 1 && relaunched.snapshot?.messages.first?.text == "new synthetic identity")
        print("PASS changed-key recovery requires removal plus fresh add and independent verification")

        let partialRemovalDeadline = now() + 2
        let expiringOther = StoredMessage(id: message(91, expiry: partialRemovalDeadline).id, sender: bob.account_id,
            recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", text: "unrelated expiry", security_alert: nil, duplicate: false, expires_at: partialRemovalDeadline)
        try Fixture.reset([expiringOther], sessionValid: true, contacts: [alice, bob])
        Fixture.identityChangedOnDecrypt = true
        Fixture.incoming = [QueuedMessage(id: message(92, expiry: 1).id, sender: alice.account_id, envelope: "changed identity", created_at: 1)]
        let partialRemoval = AppModel(); Fixture.failSave = true; await partialRemoval.refresh()
        Fixture.failSave = false; partialRemoval.retryLoad()
        precondition(partialRemoval.pendingIdentityChanges == [alice.account_id])
        Fixture.delaySaveUntil = partialRemovalDeadline; Fixture.failAtWrite = Fixture.writes + 2
        let failedCleanup = await partialRemoval.removeContact(removal)
        if case .failed = failedCleanup {} else { preconditionFailure("Expected second cleanup save failure") }
        precondition(partialRemoval.fatalError != nil && partialRemoval.snapshot == nil)
        Fixture.failAtWrite = nil; Fixture.incoming = []; partialRemoval.retryLoad()
        precondition(partialRemoval.fatalError == nil && partialRemoval.snapshot?.contacts == [bob])
        precondition(partialRemoval.pendingIdentityChanges.isEmpty && partialRemoval.snapshot?.messages.isEmpty == true)
        print("PASS durable removal survives a second expiry-write failure without replaying old observed warning")

        for failure in ["auth", "save-intent", "remote", "receipt-save", "local-clear", "journal-clear"] {
            try Fixture.reset([message(100, expiry: now() + 60)], sessionValid: true, contacts: [alice])
            let deleting = AppModel(); let original = Fixture.saved
            Fixture.authAccountID = failure == "auth" ? "18ae18f2-64c2-4442-a0aa-fe2ef8d2d130" : "81d1a713-5b97-4257-bfb4-f094a2004296"
            Fixture.failOperationSave = failure == "save-intent"
            Fixture.failRemoteOperation = failure == "remote"
            Fixture.failReceiptSave = failure == "receipt-save"
            Fixture.failClearAccount = failure == "local-clear"
            Fixture.failClearOperation = failure == "journal-clear"
            await deleting.beginAccountDeletion()
            if ["auth", "save-intent"].contains(failure) {
                precondition(Fixture.operationRequests.isEmpty && Fixture.operation == nil && Fixture.saved == original)
            } else {
                precondition(deleting.snapshot == nil && Fixture.operation != nil)
                if failure != "journal-clear" { precondition(Fixture.saved == original) }
                let exact = Fixture.operation!
                Fixture.failRemoteOperation = false; Fixture.failReceiptSave = false; Fixture.failClearAccount = false; Fixture.failClearOperation = false
                let retry = AppModel()
                precondition(retry.snapshot == nil && retry.pendingAccountOperation == .delete)
                await retry.resumeAccountOperation()
                precondition(Fixture.saved == nil && Fixture.operation == nil && retry.pendingAccountOperation == nil)
                precondition(Fixture.operationRequests.allSatisfy { $0.operationID == exact.operationID && $0.expectedGeneration == exact.expectedGeneration })
            }
        }
        print("PASS deletion binds fresh account, journals before request and resumes safely across every storage/network boundary")

        try Fixture.reset([message(101, expiry: now() + 60)], sessionValid: true)
        Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.holdAccountOperation = true
        let deletingAwait = AppModel(); let originalDeleteState = Fixture.saved
        let deletion = Task { await deletingAwait.beginAccountDeletion() }
        try await waitUntil { Fixture.heldAccountOperation != nil }
        precondition(Fixture.saved == originalDeleteState && deletingAwait.snapshot == nil)
        let pausedSend = await deletingAwait.send(text: "cannot send", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296")
        precondition(!pausedSend && Fixture.sent.isEmpty)
        Fixture.heldAccountOperation?.resume(); Fixture.heldAccountOperation = nil
        await deletion.value
        precondition(Fixture.saved == nil && Fixture.operation == nil)
        print("PASS pending deletion pauses sends and retains original keys until server confirmation")

        for mismatch in [false, true] {
            try Fixture.reset([], sessionValid: true)
            Fixture.saved = nil; Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.registrationExists = true
            let reenrolling = AppModel(); await reenrolling.signIn()
            precondition(reenrolling.reenrollmentAccountID == "81d1a713-5b97-4257-bfb4-f094a2004296" && Fixture.saved == nil)
            reenrolling.alert = nil; Fixture.failRemoteOperation = true
            await reenrolling.beginReenrollment()
            precondition(Fixture.saved == nil && Fixture.operation?.preparedCore != nil && reenrolling.snapshot == nil)
            let exact = Fixture.operation!
            Fixture.failRemoteOperation = false; Fixture.mismatchOwnKeys = mismatch
            let retry = AppModel(); await retry.resumeAccountOperation()
            precondition(Fixture.operationRequests.count == 2 && Fixture.operationRequests.allSatisfy { $0 == exact })
            if mismatch {
                precondition(Fixture.saved == nil && Fixture.operation?.completed == true && retry.snapshot == nil)
            } else {
                precondition(Fixture.operation == nil && retry.snapshot?.fingerprint == newFingerprint && Fixture.saved?.registered == true)
                precondition(retry.pendingAccountOperation == nil && retry.snapshot?.key_maintenance.initial_upload_pending == false)
            }
        }
        print("PASS re-enrollment retains exact proposed keys across uncertain replies and refuses a superseded server identity")

        // Expired unexecuted intent is cancellable only after signed state proves
        // the original generation/pin still exists past the fixed deadline.
        try Fixture.reset([message(110, expiry: now() + 60)], sessionValid: true)
        Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.failRemoteOperation = true
        let expiredIntent = AppModel(); await expiredIntent.beginAccountDeletion()
        let savedIntent = Fixture.operation!
        Fixture.failRemoteOperation = false; Fixture.conflictOperation = true
        Fixture.operationServerTime = savedIntent.expiresAt
        await expiredIntent.resumeAccountOperation()
        precondition(expiredIntent.canCancelAccountOperation && !expiredIntent.canDiscardAccountOperation)
        precondition(Fixture.operation == savedIntent && Fixture.loginCalls == 1)
        expiredIntent.cancelExpiredAccountOperation()
        precondition(Fixture.operation == nil && expiredIntent.snapshot?.messages.count == 1)
        print("PASS expired unexecuted operation restores old account only after explicit cancellation")

        // A historical receipt is tried before current account state, so a new
        // generation cannot strand cleanup or be deleted by the old request.
        try Fixture.reset([], sessionValid: true)
        Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.failRemoteOperation = true
        let historicalReceipt = AppModel(); await historicalReceipt.beginAccountDeletion()
        Fixture.failRemoteOperation = false
        Fixture.remoteGeneration = "00000000-0000-4000-8000-000000000099"
        await historicalReceipt.resumeAccountOperation()
        precondition(Fixture.saved == nil && Fixture.operation == nil && Fixture.loginCalls == 1)
        print("PASS historical deletion receipt completes local cleanup despite recreated remote generation")

        // After receipt collection, an absent account is reconciled without
        // asking for a passkey that account deletion has already removed.
        try Fixture.reset([], sessionValid: true)
        Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.failRemoteOperation = true
        let goneAccount = AppModel(); await goneAccount.beginAccountDeletion()
        Fixture.failRemoteOperation = false; Fixture.conflictOperation = true; Fixture.remoteAbsent = true
        await goneAccount.resumeAccountOperation()
        precondition(Fixture.saved == nil && Fixture.operation == nil && Fixture.loginCalls == 1)
        print("PASS expired deletion receipt plus absent registration clears locally without account creation")

        for remoteState in ["prepared", "absent", "superseded"] {
            try Fixture.reset([], sessionValid: true)
            Fixture.saved = nil; Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.registrationExists = true
            let recovery = AppModel(); await recovery.signIn()
            Fixture.failRemoteOperation = true; await recovery.beginReenrollment()
            let prepared = Fixture.operation!
            Fixture.failRemoteOperation = false; Fixture.conflictOperation = true
            Fixture.operationServerTime = prepared.expiresAt + 86_400
            Fixture.remoteAbsent = remoteState == "absent"
            Fixture.remoteFingerprint = remoteState == "prepared" ? prepared.preparedFingerprint : String(repeating: "c", count: 64)
            Fixture.remoteGeneration = "00000000-0000-4000-8000-000000000099"
            let beforeLogin = Fixture.loginCalls
            await recovery.resumeAccountOperation()
            if remoteState == "prepared" {
                precondition(recovery.snapshot?.fingerprint == prepared.preparedFingerprint && Fixture.operation == nil)
                precondition(Fixture.loginCalls == beforeLogin + 1 && Fixture.saved?.registered == true)
            } else {
                precondition(Fixture.saved == nil && recovery.canDiscardAccountOperation && recovery.snapshot == nil)
                precondition(Fixture.loginCalls == beforeLogin && Fixture.operation?.operationID == prepared.operationID)
                recovery.discardPendingLocalAccount()
                precondition(Fixture.operation == nil && recovery.reenrollmentAccountID == "81d1a713-5b97-4257-bfb4-f094a2004296")
            }
        }
        print("PASS collected reenrollment receipt recovers only matching prepared keys; absent/superseded accounts need explicit restart")

        try Fixture.reset([], sessionValid: true)
        Fixture.saved = nil; Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.registrationExists = true
        let completedRecovery = AppModel(); await completedRecovery.signIn()
        Fixture.mismatchOwnKeys = true
        await completedRecovery.beginReenrollment()
        precondition(Fixture.operation?.completed == true && completedRecovery.snapshot == nil)
        Fixture.remoteGeneration = "00000000-0000-4000-8000-000000000099"
        Fixture.remoteFingerprint = String(repeating: "c", count: 64)
        Fixture.operationServerTime = Fixture.operation!.expiresAt
        await completedRecovery.resumeAccountOperation()
        precondition(completedRecovery.canDiscardAccountOperation && !completedRecovery.canCancelAccountOperation)
        precondition(Fixture.saved == nil && Fixture.operation?.completed == true)
        completedRecovery.discardPendingLocalAccount()
        precondition(Fixture.operation == nil && Fixture.saved == nil)
        print("PASS superseded completed reenrollment offers explicit local restart without adopting mismatched keys")

        for registration in ["changed", "missing", "interrupted-initial"] {
            try Fixture.reset([message(111, expiry: now() + 60)], contacts: [alice])
            Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"
            Fixture.mismatchOwnKeys = registration == "changed"
            Fixture.missingOwnKeys = registration != "changed"
            if registration == "interrupted-initial" { Fixture.saved?.registered = false }
            let oldDevice = AppModel(); await oldDevice.signIn()
            precondition(oldDevice.snapshot == nil && oldDevice.replacedDeviceAccountID == "81d1a713-5b97-4257-bfb4-f094a2004296")
            precondition(Fixture.saved?.identityReplaced == true && Fixture.saved?.token == "")
            precondition(Fixture.uploads == 0 && Fixture.permissionUpdates == 0 && Fixture.sent.isEmpty && Fixture.acknowledgements == 0)
            do { try await oldDevice.updatePushToken("synthetic"); preconditionFailure("Locked identity updated push") } catch {}
            await oldDevice.refresh()
            let lockedSend = await oldDevice.send(text: "blocked", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296")
            precondition(!lockedSend && Fixture.pushUpdates == 0 && Fixture.sent.isEmpty)
            let relaunch = AppModel()
            precondition(relaunch.snapshot == nil && relaunch.replacedDeviceAccountID == "81d1a713-5b97-4257-bfb4-f094a2004296")
            relaunch.discardReplacedDevice()
            precondition(Fixture.saved == nil && relaunch.reenrollmentAccountID == "81d1a713-5b97-4257-bfb4-f094a2004296")
        }
        print("PASS stale or missing device registration never publishes renewed session or restores retired keys")

        let lockedDeadline = now() + 2
        try Fixture.reset([message(112, expiry: lockedDeadline)], sessionValid: true)
        Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.holdAccountOperation = true
        let lockedDeletion = AppModel(); lockedDeletion.setAppActive(true)
        let waitingDelete = Task { await lockedDeletion.beginAccountDeletion() }
        try await waitUntil { Fixture.heldAccountOperation != nil }
        try await waitPast(lockedDeadline)
        let prunedLocked = try Fixture.snapshot(Fixture.saved!.core)
        precondition(prunedLocked.messages.isEmpty && lockedDeletion.snapshot == nil && Fixture.operation != nil)
        precondition(Fixture.saved?.unreadMessageIDs.isEmpty == true)
        Fixture.failRemoteOperation = true
        Fixture.heldAccountOperation?.resume(); Fixture.heldAccountOperation = nil
        await waitingDelete.value
        lockedDeletion.setAppActive(false)
        precondition(Fixture.saved != nil && Fixture.operation != nil)
        print("PASS pending deletion prunes original plaintext on deadline while server request remains suspended")

        let replacedDeadline = now() + 2
        try Fixture.reset([message(113, expiry: replacedDeadline)], sessionValid: true)
        Fixture.saved?.identityReplaced = true
        let replacedRetention = AppModel(); replacedRetention.setAppActive(true)
        try await waitPast(replacedDeadline)
        let prunedReplaced = try Fixture.snapshot(Fixture.saved!.core)
        precondition(prunedReplaced.messages.isEmpty && replacedRetention.snapshot == nil && Fixture.saved?.identityReplaced == true)
        replacedRetention.setAppActive(false)
        print("PASS replaced-device account retains identity marker but durably expires hidden history offline")

        try Fixture.reset([], sessionValid: true)
        let stagingURL = URL(string: "https://api-staging.isyeet.io")!
        let productionURL = URL(string: "https://api.isyeet.io")!
        let originalCore = Fixture.saved!.core
        Fixture.serverURL = stagingURL
        Fixture.saved = StoredAccount(version: 2, backend: stagingURL.absoluteString, account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"),
            token: "staging token", expiresAt: Int64.max, core: originalCore, registered: true)
        Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.failRemoteOperation = true
        let staging = AppModel(); await staging.beginAccountDeletion()
        let originalStagingAccount = Fixture.saved
        let originalStagingIntent = Fixture.operation
        precondition(staging.pendingAccountOperation == .delete)
        Fixture.serverURL = productionURL; Fixture.failRemoteOperation = false
        let production = AppModel()
        precondition(production.snapshot == nil && production.pendingAccountOperation == nil && production.isProduction)
        precondition(Fixture.saved == nil && Fixture.operation == nil)
        await production.signIn()
        precondition(production.snapshot?.fingerprint == String(repeating: "b", count: 64))
        precondition(Fixture.saved?.backend == productionURL.absoluteString && Fixture.saved?.token == "renewed synthetic")
        precondition(Fixture.accounts[stagingURL.absoluteString] == originalStagingAccount)
        precondition(Fixture.operations[stagingURL.absoluteString] == originalStagingIntent)
        Fixture.serverURL = stagingURL
        let restoredStaging = AppModel()
        precondition(restoredStaging.snapshot == nil && restoredStaging.pendingAccountOperation == .delete && !restoredStaging.isProduction)
        precondition(Fixture.saved == originalStagingAccount && Fixture.operation == originalStagingIntent)
        print("PASS production requires separate enrollment and never adopts or deletes staging account or operation journal")

        try Fixture.reset([], sessionValid: true)
        Fixture.saved = nil; Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"; Fixture.failUpload = true
        let initialSignup = AppModel(); await initialSignup.signIn()
        precondition(Fixture.saved?.registered == false && initialSignup.snapshot?.key_maintenance.initial_upload_pending == true)
        let initialKeys = Fixture.saved!.core
        Fixture.missingOwnKeys = true; Fixture.failUpload = false
        await initialSignup.refresh()
        precondition(initialSignup.replacedDeviceAccountID == nil && Fixture.saved?.registered == true)
        precondition(initialSignup.snapshot?.key_maintenance.initial_upload_pending == false && Fixture.uploads == 2)
        guard case .object(let beforeKeys) = initialKeys, case .object(let afterKeys) = Fixture.saved!.core else { preconditionFailure() }
        precondition(beforeKeys["identity"] == afterKeys["identity"])
        print("PASS original saved session retries initial upload; fresh passkey login never republishes a missing registration")

        for missing in [false, true] {
            try Fixture.reset([], sessionValid: true)
            Fixture.saved?.registered = false; Fixture.missingOwnKeys = missing
            let migratedUpload = AppModel(); await migratedUpload.refresh()
            precondition(Fixture.uploads == 0)
            if missing {
                precondition(migratedUpload.snapshot == nil && Fixture.saved?.identityReplaced == true)
            } else {
                precondition(Fixture.saved?.registered == true && migratedUpload.replacedDeviceAccountID == nil)
            }
        }
        print("PASS migrated unregistered state validates existing keys or locks, never republishes through refresh")

        for response in ["network-failure", "unknown-signed-key", "matching-ack-lost"] {
            try Fixture.reset([], sessionValid: true)
            Fixture.authAccountID = "81d1a713-5b97-4257-bfb4-f094a2004296"
            Fixture.failOwnKeys = response == "network-failure"
            Fixture.mismatchSignedKeys = response == "unknown-signed-key"
            if response == "matching-ack-lost" {
                let initial = try Fixture.snapshot(Fixture.saved!.core)
                Fixture.saved?.core = try Fixture.replacing(Fixture.saved!.core, snapshot: Fixture.updated(initial, maintenance: KeyMaintenanceState(initial_upload_pending: true)))
                Fixture.saved?.registered = false
            }
            let renewal = AppModel(); let original = Fixture.saved
            await renewal.signIn()
            if response == "network-failure" {
                precondition(Fixture.saved == original && renewal.replacedDeviceAccountID == nil)
            } else if response == "unknown-signed-key" {
                precondition(Fixture.saved?.identityReplaced == true && Fixture.saved?.token == "")
            } else {
                precondition(Fixture.saved?.registered == true && renewal.snapshot?.key_maintenance.initial_upload_pending == false)
                precondition(Fixture.saved?.token == "renewed synthetic")
            }
            precondition(Fixture.uploads == 0)
        }
        print("PASS passkey login validates known registration before token adoption and resolves lost initial ACK without republishing")

        for failure in ["prepare-save", "http", "receipt", "confirm-save"] {
            try Fixture.reset([], sessionValid: true)
            let baseline = try Fixture.snapshot(Fixture.saved!.core)
            Fixture.saved?.core = try Fixture.replacing(Fixture.saved!.core, snapshot: Fixture.updated(baseline, maintenance: KeyMaintenanceState(next_check_at: 0)))
            let maintaining = AppModel(); let originalState = Fixture.saved!.core
            if failure == "prepare-save" { Fixture.failSave = true }
            Fixture.failMaintenance = failure == "http"
            Fixture.mismatchMaintenanceReceipt = failure == "receipt"
            if failure == "confirm-save" { Fixture.failAtWrite = Fixture.writes + 2 }
            await maintaining.refresh()
            if failure == "prepare-save" {
                precondition(Fixture.maintenanceRequests.isEmpty && Fixture.saved?.core == originalState)
            } else {
                precondition(Fixture.maintenanceRequests.count == 1 && maintaining.snapshot?.key_maintenance.pending != nil)
                let exact = Fixture.maintenanceRequests[0]
                Fixture.failMaintenance = false; Fixture.mismatchMaintenanceReceipt = false; Fixture.failAtWrite = nil
                let reads = Fixture.maintenanceReads
                await maintaining.refresh()
                precondition(Fixture.maintenanceReads == reads && Fixture.maintenanceRequests == [exact, exact])
                precondition(maintaining.snapshot?.key_maintenance.pending == nil)
                await maintaining.refresh()
                precondition(Fixture.maintenanceReads == reads && Fixture.maintenanceRequests.count == 2)
            }
        }
        print("PASS prekey maintenance saves private proposal before PUT and retries exact pending request across HTTP/receipt/save failures")

        let maintenanceDeadline = now() + 2
        try Fixture.reset([message(125, expiry: maintenanceDeadline)], sessionValid: true)
        let maintenanceBaseline = try Fixture.snapshot(Fixture.saved!.core)
        Fixture.saved?.core = try Fixture.replacing(Fixture.saved!.core, snapshot: Fixture.updated(maintenanceBaseline, maintenance: KeyMaintenanceState(next_check_at: 0)))
        Fixture.holdMaintenance = true
        let maintenanceExpiry = AppModel(); maintenanceExpiry.setAppActive(true)
        let maintenanceTask = Task { await maintenanceExpiry.refresh() }
        try await waitUntil { Fixture.heldMaintenance != nil }; try await waitPast(maintenanceDeadline)
        precondition(maintenanceExpiry.snapshot?.messages.isEmpty == true && maintenanceExpiry.snapshot?.key_maintenance.pending != nil)
        Fixture.heldMaintenance?.resume(); Fixture.heldMaintenance = nil
        await maintenanceTask.value
        precondition(maintenanceExpiry.snapshot?.messages.isEmpty == true && maintenanceExpiry.snapshot?.key_maintenance.pending == nil)
        maintenanceExpiry.setAppActive(false)
        print("PASS delayed prekey receipt adopts latest expired state without resurrecting message history")

        try Fixture.reset([], sessionValid: true)
        let inboxMaintenance = try Fixture.snapshot(Fixture.saved!.core)
        Fixture.saved?.core = try Fixture.replacing(Fixture.saved!.core, snapshot: Fixture.updated(inboxMaintenance, maintenance: KeyMaintenanceState(next_check_at: 0)))
        Fixture.failMaintenance = true
        Fixture.incoming = [QueuedMessage(id: message(126, expiry: 1).id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", envelope: "synthetic", created_at: 1)]
        Fixture.directArrival = message(126, expiry: now() + 60)
        let receiveBeforeMaintenance = AppModel(); await receiveBeforeMaintenance.refresh()
        precondition(Fixture.acknowledgements == 1 && receiveBeforeMaintenance.snapshot?.messages.count == 1)
        precondition(Fixture.maintenanceRequests.count == 1 && receiveBeforeMaintenance.synchronizationSequence == 1)
        print("PASS failed maintenance does not starve authenticated inbox processing or durable ACK")

        try Fixture.reset([], sessionValid: true)
        Fixture.selfMessages = true; Fixture.holdSend = true; Fixture.holdInbox = true
        let loopback = AppModel()
        let selfSend = Task { await loopback.send(text: "ASCII self-test **literal**", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296") }
        try await waitUntil { Fixture.heldSend != nil }
        precondition(loopback.snapshot?.outbox.count == 1 && loopback.snapshot?.messages.isEmpty == true)
        Fixture.heldSend?.resume(); Fixture.heldSend = nil
        try await waitUntil { Fixture.heldInbox != nil }
        precondition(loopback.snapshot?.outbox.isEmpty == true && loopback.snapshot?.messages.isEmpty == true)
        precondition(loopback.checkingInbox)
        precondition(Fixture.acknowledgements == 0 && Fixture.keyClaims == 0)
        Fixture.heldInbox?.resume(); Fixture.heldInbox = nil
        let selfSent = await selfSend.value
        precondition(selfSent && Fixture.acknowledgements == 1 && loopback.snapshot?.contacts.isEmpty == true)
        precondition(loopback.snapshot?.messages.first?.sender == "81d1a713-5b97-4257-bfb4-f094a2004296" && loopback.snapshot?.messages.first?.recipient == "81d1a713-5b97-4257-bfb4-f094a2004296")
        precondition(loopback.snapshot?.messages.first?.text == "ASCII self-test **literal**")
        precondition(loopback.unreadCount == 0 && !loopback.showsNewMessageIndicator && loopback.unreadArrivalSequence == 0)
        precondition(!loopback.checkingInbox)
        let restoredSelf = AppModel()
        precondition(restoredSelf.snapshot?.messages.count == 1 && restoredSelf.unreadCount == 0)
        await restoredSelf.refresh()
        precondition(restoredSelf.snapshot?.messages.count == 1 && Fixture.acknowledgements == 2 && restoredSelf.unreadCount == 0)
        print("PASS self message appears only after relay-return processing, with no key claim, contact or unread echo")

        try Fixture.reset([], sessionValid: true)
        Fixture.selfMessages = true; Fixture.failSend = true
        let retrySelf = AppModel()
        let queuedSelf = await retrySelf.send(text: "retry self", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296")
        precondition(queuedSelf && retrySelf.snapshot?.outbox.count == 1 && retrySelf.snapshot?.messages.isEmpty == true)
        let originalSelfID = retrySelf.snapshot?.outbox.first?.id
        Fixture.failSend = false
        await retrySelf.refresh()
        precondition(retrySelf.snapshot?.outbox.isEmpty == true && retrySelf.snapshot?.messages.first?.id == originalSelfID)
        precondition(Fixture.sent.count == 2 && Set(Fixture.sent).count == 1 && Fixture.acknowledgements == 1)
        print("PASS self retry retains original ciphertext ID and no local plaintext echo")

        try Fixture.reset([], sessionValid: true)
        Fixture.selfMessages = true; Fixture.rejectSelfReturn = true
        let rejectedSelf = AppModel()
        _ = await rejectedSelf.send(text: "synthetic rejected return", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296")
        precondition(rejectedSelf.snapshot?.messages.first?.text == nil && rejectedSelf.snapshot?.messages.first?.security_alert != nil)
        precondition(rejectedSelf.unreadCount == 0 && !rejectedSelf.showsNewMessageIndicator && rejectedSelf.alert != nil)
        print("PASS rejected self return produces only a generic security alert, never received plaintext")

        try Fixture.reset([], sessionValid: true)
        Fixture.selfMessages = true
        let failedSelfSave = AppModel()
        Fixture.failSave = true
        let failedSelfSend = await failedSelfSave.send(text: "unsaved self-test", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296")
        precondition(!failedSelfSend && Fixture.sent.isEmpty && failedSelfSave.snapshot?.messages.isEmpty == true)
        precondition(failedSelfSave.snapshot?.outbox.isEmpty == true && Fixture.acknowledgements == 0)
        print("PASS self encryption save failure cannot send or show a received message")

        try Fixture.reset([], sessionValid: true)
        Fixture.selfMessages = true; Fixture.holdInbox = true
        let failedReturn = AppModel()
        let returnSend = Task { await failedReturn.send(text: "durable return test", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296") }
        try await waitUntil { Fixture.heldInbox != nil }
        Fixture.failSave = true
        Fixture.heldInbox?.resume(); Fixture.heldInbox = nil
        let returnWasQueued = await returnSend.value
        precondition(returnWasQueued && Fixture.sent.count == 1 && Fixture.acknowledgements == 0)
        precondition(failedReturn.snapshot?.messages.isEmpty == true && !failedReturn.checkingInbox)
        Fixture.failSave = false
        await failedReturn.refresh()
        precondition(failedReturn.snapshot?.messages.first?.text == "durable return test" && Fixture.acknowledgements == 1)
        print("PASS self return save failure withholds history and ACK until durable retry")

        try Fixture.reset([], sessionValid: true)
        let ownContact = AppModel()
        await ownContact.addContact("me_test")
        precondition(ownContact.alert == SafetyError.selfContact.errorDescription && Fixture.keyClaims == 0)
        precondition(ownContact.snapshot?.contacts.isEmpty == true)
        print("PASS adding own canonical address directs to Message yourself without directory lookup")

        let groupAlice = Contact(account_id: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", username: testUsername("0beaac69-d53e-48d2-b5aa-dd405b7f414d"), fingerprint: String(repeating: "b", count: 64), verified: true)
        let groupBob = Contact(account_id: "300db02d-b75a-4922-8759-f08a0efa5a40", username: testUsername("300db02d-b75a-4922-8759-f08a0efa5a40"), fingerprint: String(repeating: "c", count: 64), verified: true)
        let testGroup = MessageGroup(id: String(repeating: "1", count: 64), title: "Test group",
                                    members: [.init(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", fingerprint: String(repeating: "a", count: 64)),
                                              .init(account_id: groupAlice.account_id, fingerprint: groupAlice.fingerprint),
                                              .init(account_id: groupBob.account_id, fingerprint: groupBob.fingerprint)], blocked: false)
        try Fixture.reset([], sessionValid: true, contacts: [groupAlice, groupBob])
        let fanout = AppModel()
        Fixture.failSave = true
        let failedCreation = await fanout.createGroup(title: "Test group", members: [groupAlice.account_id, groupBob.account_id])
        precondition(failedCreation == nil && fanout.snapshot?.groups.isEmpty == true)
        Fixture.failSave = false
        let createdGroup = await fanout.createGroup(title: "Test group", members: [groupAlice.account_id, groupBob.account_id])
        precondition(createdGroup == testGroup.id && fanout.snapshot?.groups.first == testGroup)
        Fixture.failSave = true
        let failedFanout = await fanout.sendGroup(text: "never leave unsaved state", groupID: testGroup.id)
        precondition(!failedFanout && Fixture.sent.isEmpty && fanout.snapshot?.messages.isEmpty == true && fanout.snapshot?.outbox.isEmpty == true)
        Fixture.failSave = false
        Fixture.failedRecipients = [groupBob.account_id]
        let acceptedLocally = await fanout.sendGroup(text: "two encrypted recipients", groupID: testGroup.id)
        precondition(acceptedLocally && Fixture.sent.count == 2 && fanout.snapshot?.outbox.count == 1)
        precondition(fanout.snapshot?.messages.first?.status == "partially_accepted" && fanout.snapshot?.messages.first?.accepted_count == 1)
        precondition(fanout.snapshot?.messages.first?.recipient_count == 2 && fanout.unreadCount == 0)
        let retainedLeg = fanout.snapshot?.outbox.first?.id
        Fixture.failedRecipients = []
        await fanout.refresh()
        precondition(Fixture.sent.last == retainedLeg && fanout.snapshot?.outbox.isEmpty == true)
        precondition(fanout.snapshot?.messages.first?.status == "relay_accepted" && fanout.snapshot?.messages.first?.accepted_count == 2)
        print("PASS group creation/fanout save atomically before send and independent relay acceptance retries")

        let groupHistory = fanout.snapshot!.messages[0]
        let otherLeg = SendRequest(id: "00000000-0000-4000-8000-000000000501", recipient: groupBob.account_id,
                                   envelope: "synthetic remaining leg", expires_at: now() + 60)
        let otherRef = OutboxReference(id: otherLeg.id, group_id: testGroup.id, message_id: groupHistory.id, recipient: otherLeg.recipient)
        try Fixture.reset([groupHistory], outbox: [otherLeg], sessionValid: true, contacts: [groupAlice, groupBob], groups: [testGroup], refs: [otherRef])
        Fixture.saved!.contactIdentityChanges = [groupAlice.account_id]
        let warnedGroup = AppModel()
        precondition(warnedGroup.groupIsBlocked(testGroup.id) && warnedGroup.snapshot?.groups.first?.blocked == true)
        precondition(warnedGroup.snapshot?.outbox.isEmpty == true)
        await warnedGroup.refresh()
        let blockedFanout = await warnedGroup.sendGroup(text: "blocked", groupID: testGroup.id)
        let blockedCreation = await warnedGroup.createGroup(title: "Not allowed", members: [groupAlice.account_id, groupBob.account_id])
        precondition(!blockedFanout && blockedCreation == nil && Fixture.sent.isEmpty)
        print("PASS one member warning cancels every group leg including other recipients and blocks creation")

        let pendingGroupMessage = StoredMessage(id: "00000000-0000-4000-8000-000000000510", sender: groupAlice.account_id,
                                               recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", text: "hidden pending verification", security_alert: nil,
                                               duplicate: false, expires_at: now() + 60, group_id: testGroup.id,
                                               received_at: now() - 3, status: "received")
        try Fixture.reset([], sessionValid: true, contacts: [groupAlice, groupBob])
        Fixture.resolutionGroup = testGroup; Fixture.allowResolve = true
        guard case var .object(warningCore) = Fixture.saved!.core else { fatalError() }
        warningCore["pending_resolutions"] = try Fixture.json([pendingGroupMessage])
        Fixture.saved!.core = .object(warningCore); Fixture.saved!.contactIdentityChanges = [groupBob.account_id]
        let warnedUnknownGroup = AppModel()
        precondition(warnedUnknownGroup.snapshot?.messages.isEmpty == true && warnedUnknownGroup.snapshot?.groups.isEmpty == true)
        precondition(warnedUnknownGroup.snapshot?.pending_group_senders == [groupAlice.account_id])
        warnedUnknownGroup.maintainLocalMessages()
        precondition(warnedUnknownGroup.snapshot?.messages.isEmpty == true && warnedUnknownGroup.unreadCount == 0)
        print("PASS warning migration precedes unknown-group quarantine promotion from a different sender")

        let oldHistory = message(511, expiry: now() + 60)
        try Fixture.reset([oldHistory], sessionValid: true, contacts: [groupAlice, groupBob])
        Fixture.saved!.unreadMessageIDs = []
        Fixture.resolutionGroup = testGroup; Fixture.allowResolve = true
        guard case var .object(startupCore) = Fixture.saved!.core else { fatalError() }
        startupCore["pending_resolutions"] = try Fixture.json([pendingGroupMessage]); Fixture.saved!.core = .object(startupCore)
        let startupResolved = AppModel()
        precondition(startupResolved.snapshot?.groups.first == testGroup && startupResolved.unreadCounts == [testGroup.conversationID: 1])
        precondition(Fixture.saved?.unreadMessageIDs == [pendingGroupMessage.id] && startupResolved.unreadArrivalSequence == 1)
        precondition(startupResolved.snapshot?.messages.last?.received_at == pendingGroupMessage.received_at)
        let resolutionRelaunch = AppModel()
        precondition(resolutionRelaunch.unreadCount == 1 && resolutionRelaunch.unreadArrivalSequence == 0)
        print("PASS startup quarantine resolution saves new group unread without inventing historical unread")

        let detailsDeadline = now() + 2
        let detailArrival = try Fixture.changedMessage(pendingGroupMessage, ["expires_at": .integer(detailsDeadline)])
        try Fixture.reset([], sessionValid: true, contacts: [groupAlice, groupBob])
        Fixture.resolutionGroup = testGroup; Fixture.deferredArrival = detailArrival
        Fixture.incoming = [QueuedMessage(id: detailArrival.id, sender: groupAlice.account_id, envelope: "synthetic deferred group", created_at: now())]
        let coveredGroup = AppModel(); coveredGroup.setAppActive(true)
        coveredGroup.conversationDidAppear(testGroup.conversationID)
        coveredGroup.setPresentationCovered("message-details", covered: true)
        await coveredGroup.refresh()
        precondition(Fixture.acknowledgements == 1 && coveredGroup.snapshot?.messages.isEmpty == true && coveredGroup.unreadCount == 0)
        precondition(coveredGroup.synchronizationSequence == 0)
        Fixture.allowResolve = true
        coveredGroup.maintainLocalMessages()
        let detailsSelection = MessageSelection(id: detailArrival.id)
        precondition(coveredGroup.unreadCounts == [testGroup.conversationID: 1] && coveredGroup.showsNewMessageIndicator)
        precondition(coveredGroup.snapshot?.message(id: detailsSelection.id, at: now())?.text == detailArrival.text)
        coveredGroup.setPresentationCovered("message-details", covered: false)
        precondition(coveredGroup.unreadCount == 0)
        coveredGroup.setPresentationCovered("message-details", covered: true)
        try await waitPast(detailsDeadline)
        precondition(coveredGroup.snapshot?.message(id: detailsSelection.id, at: now()) == nil)
        let expiredDetailsSaved = try Fixture.snapshot(Fixture.saved!.core)
        precondition(expiredDetailsSaved.messages.isEmpty)
        coveredGroup.setAppActive(false)
        print("PASS covered group arrival stays unread, details use live ID, and active expiry removes durable content")

        try Fixture.reset([], sessionValid: true, contacts: [groupAlice, groupBob])
        Fixture.resolutionGroup = testGroup; Fixture.deferredArrival = pendingGroupMessage
        Fixture.incoming = [QueuedMessage(id: pendingGroupMessage.id, sender: groupAlice.account_id, envelope: "synthetic pending group", created_at: now())]
        let failedQuarantine = AppModel(); Fixture.failSave = true
        await failedQuarantine.refresh()
        precondition(Fixture.acknowledgements == 0 && failedQuarantine.snapshot?.messages.isEmpty == true)
        Fixture.failSave = false
        await failedQuarantine.refresh()
        precondition(Fixture.acknowledgements == 1 && failedQuarantine.snapshot?.messages.isEmpty == true)
        Fixture.allowResolve = true; Fixture.failSave = true
        failedQuarantine.maintainLocalMessages()
        precondition(failedQuarantine.fatalError != nil && failedQuarantine.snapshot == nil && failedQuarantine.unreadCount == 0)
        Fixture.failSave = false
        failedQuarantine.retryLoad()
        precondition(failedQuarantine.fatalError == nil && failedQuarantine.unreadCounts == [testGroup.conversationID: 1])
        precondition(failedQuarantine.snapshot?.messages.first?.id == pendingGroupMessage.id && Fixture.acknowledgements == 1)
        print("PASS quarantine save precedes ACK and resolution save failure withholds text/unread until recovery")

        try Fixture.reset([], sessionValid: true)
        let enabling = AppModel(); enabling.setAppActive(true)
        let beforeEnableWrites = Fixture.writes
        Fixture.failMode = true
        await enabling.setTrafficMode(.cover)
        precondition(enabling.trafficMode == .notifications && !Fixture.remoteCover && Fixture.writes == beforeEnableWrites)
        Fixture.failMode = false; Fixture.failSave = true
        await enabling.setTrafficMode(.cover)
        precondition(Fixture.remoteCover && enabling.trafficMode == .notifications && !enabling.coverServerConfirmed)
        Fixture.failSave = false
        await enabling.refresh(quiet: true)
        precondition(!Fixture.remoteCover && enabling.trafficMode == .notifications)
        await enabling.setTrafficMode(.cover)
        precondition(enabling.trafficMode == .cover && enabling.coverServerConfirmed && Fixture.remoteCover)
        let savedEnabled = try Fixture.snapshot(Fixture.saved!.core)
        precondition(savedEnabled.traffic.enabled)
        enabling.setAppActive(false)
        print("PASS server quiet precedes durable cover consent; failed transition recovers without advertising consent")

        var coverTraffic = TrafficState(); coverTraffic.enabled = true
        let firstReal = envelope(800, expiry: now() + 60), secondReal = envelope(801, expiry: now() + 60)
        try Fixture.reset([], outbox: [firstReal, secondReal], sessionValid: true, traffic: coverTraffic)
        Fixture.remoteCover = true
        let slotted = AppModel(); slotted.setAppActive(true)
        await slotted.refresh(quiet: true)
        await slotted.refresh(quiet: true)
        precondition(Fixture.sent.isEmpty && slotted.snapshot?.outbox.count == 2)
        Fixture.holdSend = true
        let slot = Task { await slotted.sendCoverSlot() }
        try await waitUntil { Fixture.heldSend != nil }
        await slotted.sendCoverSlot()
        await slotted.refresh(quiet: true)
        precondition(Fixture.sent == [firstReal.id])
        Fixture.heldSend?.resume(); Fixture.heldSend = nil
        await slot.value
        precondition(slotted.snapshot?.outbox.map(\.id) == [secondReal.id])
        slotted.setAppActive(false)
        await slotted.sendCoverSlot()
        precondition(Fixture.sent.count == 1)
        slotted.setAppActive(true)
        precondition(Fixture.sent.count == 1) // Foreground starts a fresh delay, never a flush.
        await slotted.refresh(quiet: true)
        Fixture.failSend = true
        await slotted.sendCoverSlot()
        precondition(slotted.snapshot?.outbox.map(\.id) == [secondReal.id])
        Fixture.failSend = false
        await slotted.sendCoverSlot()
        precondition(Fixture.sent == [firstReal.id, secondReal.id, secondReal.id])
        precondition(slotted.snapshot?.outbox.isEmpty == true)
        slotted.setAppActive(false)
        print("PASS refresh never bypasses cover slots, one packet per slot, no inactive/resume burst, exact-ID retry after failure")

        try Fixture.reset([], outbox: [firstReal], sessionValid: true, traffic: coverTraffic)
        Fixture.remoteCover = true; Fixture.holdMode = true
        let oldConfirmation = AppModel(); oldConfirmation.setAppActive(true)
        let policyRequest = Task { await oldConfirmation.refresh(quiet: true) }
        try await waitUntil { Fixture.heldMode != nil }
        oldConfirmation.setAppActive(false)
        oldConfirmation.setAppActive(true)
        Fixture.heldMode?.resume(); Fixture.heldMode = nil
        await policyRequest.value
        precondition(!oldConfirmation.coverServerConfirmed)
        Fixture.failMode = true
        await oldConfirmation.sendCoverSlot()
        precondition(Fixture.sent.isEmpty)
        Fixture.failMode = false
        await oldConfirmation.sendCoverSlot()
        precondition(oldConfirmation.coverServerConfirmed)
        precondition(Fixture.sent == [firstReal.id])
        oldConfirmation.setAppActive(false)
        print("PASS stale policy response across background/resume cannot authorize a fresh foreground session")

        let availableRecipient = SendRequest(id: "00000000-0000-4000-8000-000000000803", recipient: "300db02d-b75a-4922-8759-f08a0efa5a40", envelope: "synthetic second recipient", expires_at: now() + 60)
        try Fixture.reset([], outbox: [firstReal, availableRecipient], sessionValid: true, traffic: coverTraffic)
        Fixture.remoteCover = true; Fixture.failedRecipients = [firstReal.recipient]
        let fairSlots = AppModel(); fairSlots.setAppActive(true)
        await fairSlots.refresh(quiet: true)
        await fairSlots.sendCoverSlot()
        await fairSlots.sendCoverSlot()
        precondition(Fixture.sent == [firstReal.id, availableRecipient.id])
        precondition(fairSlots.snapshot?.outbox.map(\.id) == [firstReal.id])
        Fixture.failedRecipients = []
        await fairSlots.sendCoverSlot()
        precondition(Fixture.sent == [firstReal.id, availableRecipient.id, firstReal.id])
        precondition(fairSlots.snapshot?.outbox.isEmpty == true)
        fairSlots.setAppActive(false)
        print("PASS unavailable first recipient cannot monopolize slots or starve another real message")

        try Fixture.reset([], outbox: [firstReal], sessionValid: true, traffic: coverTraffic)
        let clockGuard = AppModel(); clockGuard.setAppActive(true)
        await clockGuard.sendCoverSlot() // A quiet-policy false reply cannot release even real text in cover mode.
        precondition(Fixture.sent.isEmpty && Fixture.modeCalls.isEmpty)
        Fixture.remoteCover = true; Fixture.serverTimeOffset = -600
        await clockGuard.sendCoverSlot()
        precondition(Fixture.sent.isEmpty && !clockGuard.coverServerConfirmed && clockGuard.alert == nil)
        Fixture.serverTimeOffset = 0; Fixture.failSave = true
        await clockGuard.sendCoverSlot()
        precondition(Fixture.sent.isEmpty)
        Fixture.failSave = false
        await clockGuard.sendCoverSlot()
        precondition(Fixture.sent == [firstReal.id])
        let readsBeforeEmptySlot = Fixture.policyReads
        await clockGuard.sendCoverSlot()
        precondition(Fixture.policyReads == readsBeforeEmptySlot + 1 && Fixture.sent.count == 1)
        clockGuard.setAppActive(false)
        print("PASS every slot checks own policy regardless of demand; skew, false quiet policy and unsaved clock confirmation block release")

        try Fixture.reset([], sessionValid: true, traffic: coverTraffic)
        Fixture.remoteCover = true; Fixture.selfMessages = true
        let coverSelf = AppModel(); coverSelf.setAppActive(true)
        let selfQueued = await coverSelf.send(text: "Synthetic scheduled self test", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296")
        precondition(selfQueued && Fixture.sent.isEmpty && coverSelf.snapshot?.messages.isEmpty == true)
        await coverSelf.sendCoverSlot()
        precondition(Fixture.sent.count == 1 && coverSelf.snapshot?.messages.isEmpty == true)
        await coverSelf.refresh(quiet: true)
        precondition(coverSelf.snapshot?.messages.first?.text == "Synthetic scheduled self test" && coverSelf.unreadCount == 0)
        coverSelf.setAppActive(false)
        print("PASS self test waits for a cover slot and authentic relay return before display")

        coverTraffic.eligible_contacts = [groupAlice.account_id]
        try Fixture.reset([], sessionValid: true, contacts: [groupAlice, groupBob], groups: [testGroup], traffic: coverTraffic)
        Fixture.remoteCover = true
        let slottedGroup = AppModel(); slottedGroup.setAppActive(true)
        await slottedGroup.refresh(quiet: true)
        Fixture.failSend = true
        await slottedGroup.sendCoverSlot() // A retained uncertain cover must yield to newly queued real text.
        let initialCover = slottedGroup.snapshot!.traffic.cover_outbox_ids[0]
        Fixture.failSend = false
        let groupQueued = await slottedGroup.sendGroup(text: "Scheduled synthetic group", groupID: testGroup.id)
        precondition(groupQueued && Fixture.sent == [initialCover] && slottedGroup.snapshot?.outbox.count == 3)
        await slottedGroup.sendCoverSlot()
        precondition(Fixture.sent.count == 2 && Fixture.sent.last != initialCover)
        precondition(slottedGroup.snapshot?.messages.first?.accepted_count == 1)
        precondition(slottedGroup.snapshot?.messages.first?.status == "partially_accepted")
        await slottedGroup.refresh(quiet: true)
        precondition(Fixture.sent.count == 2)
        await slottedGroup.sendCoverSlot()
        precondition(Fixture.sent.count == 3 && slottedGroup.snapshot?.messages.first?.accepted_count == 2)
        precondition(slottedGroup.snapshot?.outbox.map(\.id) == [initialCover])
        slottedGroup.setAppActive(false)
        print("PASS atomic group fanout uses one slot per recipient and real queued legs take priority over a saved cover")

        coverTraffic.eligible_contacts = [groupAlice.account_id]
        try Fixture.reset([], sessionValid: true, contacts: [groupAlice], traffic: coverTraffic)
        Fixture.remoteCover = true
        let covers = AppModel(); covers.setAppActive(true)
        await covers.refresh(quiet: true)
        Fixture.failSave = true
        await covers.sendCoverSlot()
        precondition(Fixture.sent.isEmpty && covers.snapshot?.outbox.isEmpty == true)
        Fixture.failSave = false; Fixture.failSend = true
        await covers.sendCoverSlot()
        precondition(Fixture.sent.count == 1 && covers.snapshot?.traffic.cover_outbox_ids.count == 1)
        precondition(covers.snapshot?.messages.isEmpty == true && covers.unreadCount == 0)
        let queuedCoverID = covers.snapshot!.traffic.cover_outbox_ids[0]
        await covers.sendCoverSlot()
        precondition(Fixture.sent == [queuedCoverID, queuedCoverID] && covers.snapshot?.traffic.remaining_budget == 4095)
        Fixture.failMode = true
        await covers.setTrafficMode(.notifications)
        precondition(covers.trafficMode == .notifications && covers.snapshot?.outbox.isEmpty == true)
        precondition(Fixture.remoteCover && covers.trafficIssue != nil)
        Fixture.failMode = false; Fixture.failSend = false
        await covers.refresh(quiet: true)
        precondition(!Fixture.remoteCover && covers.notificationsResumeAt! > now())
        covers.setAppActive(false)
        print("PASS cover save precedes POST, retry reuses one reservation, disable revokes locally before server grace")

        try Fixture.reset([], sessionValid: true)
        Fixture.coverArrives = true
        Fixture.incoming = [QueuedMessage(id: message(802, expiry: now() + 60).id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", envelope: "synthetic cover", created_at: now())]
        let coverReceiver = AppModel()
        Fixture.failSave = true
        await coverReceiver.refresh(quiet: true)
        precondition(Fixture.acknowledgements == 0)
        Fixture.failSave = false; coverReceiver.alert = nil
        await coverReceiver.refresh(quiet: true)
        precondition(Fixture.acknowledgements == 1 && coverReceiver.unreadCount == 0)
        precondition(coverReceiver.snapshot?.messages.isEmpty == true && !coverReceiver.showsNewMessageIndicator && coverReceiver.alert == nil)
        print("PASS authenticated covers persist before ACK with no history, unread count or human alert")
        #endif
    }
}

// This adapter tests native persistence/network order only. Rust tests verify
// the signatures, canonical transcript, real expiry, and allocation rules.
extension CryptoBridge {
    private func deviceCall(_ operation: String, state: JSONValue, fields: [String: JSONValue]) throws -> CoreResult {
        guard case var .object(object) = state else { throw CoreError.rejected }
        var view: [String: JSONValue]
        if case .object(let stored) = object["device_authority_state"] { view = stored }
        else { view = ["authority": .null, "pending": .null, "approval_code": .null, "messaging_available": .bool(false)] }
        switch operation {
        case "device_authority_observe":
            let remote = fields["authority"] ?? .null
            if case .object(let signed) = view["pending"], case .object(let change) = signed["change"] {
                if remote != .null, remote == change["roster"] {
                    view["authority"] = remote; view["pending"] = .null
                    view["approval_code"] = .string("ISYEET-APPROVAL-1:" + Data("synthetic public approval".utf8).base64URL)
                } else if Fixture.devicePendingExpired && remote == view["authority"] {
                    view["pending"] = .null
                    object["burned_device_version"] = .integer(1)
                }
            }
            view["authority"] = remote
        case "device_authority_prepare":
            guard view["pending"] == .null else { throw CoreError.rejected }
            let identity = try Fixture.snapshot(state)
            let now = Int64(Date().timeIntervalSince1970)
            let certificate: JSONValue = .object(["account_id": .string(identity.account_id), "root_epoch": .string("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                "device_id": .integer(1), "identity_key": .string("synthetic"), "registration_id": .integer(1), "label": .string("Primary phone"), "request_hash": .string(String(repeating: "0", count: 64))])
            let roster: JSONValue = .object(["signature": .string("synthetic"), "roster": .object([
                "origin": fields["origin"]!, "account_id": .string(identity.account_id), "root_epoch": .string("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                "root_identity_key": .string("synthetic"), "version": .integer(1), "previous_hash": .string(String(repeating: "0", count: 64)),
                "highest_device_id": .integer(1), "issued_at": .integer(now), "expires_at": .integer(now + 86_400),
                "devices": .array([.object(["certificate": certificate, "signature": .string("synthetic")])])])])
            view["pending"] = .object(["signature": .string("synthetic"), "change": .object([
                "operation_id": .string(UUID().uuidString.lowercased()), "roster": roster, "expires_at": .integer(now + 300)])])
            view["approval_code"] = .null
            object["burned_device_version"] = .integer(1)
        case "device_authority_commit":
            guard case .object(let signed) = view["pending"], case .object(let change) = signed["change"] else { throw CoreError.rejected }
            view["authority"] = change["roster"]; view["pending"] = .null
            view["approval_code"] = .string("ISYEET-APPROVAL-1:" + Data("synthetic public approval".utf8).base64URL)
        default: throw CoreError.rejected
        }
        object["device_authority_state"] = .object(view)
        return CoreResult(state: .object(object), data: .object(view))
    }
}

extension LifecycleChecks {
    @MainActor private static func runDeviceAuthorizationChecks() async throws {
        let accountID = "81d1a713-5b97-4257-bfb4-f094a2004296"
        func pending() -> JSONValue? {
            guard case .object(let root) = Fixture.saved?.core, case .object(let view) = root["device_authority_state"] else { return nil }
            return view["pending"] == .null ? nil : view["pending"]
        }
        func setup() throws -> AppModel {
            try Fixture.reset([], sessionValid: true)
            Fixture.resetDeviceAuthorization()
            Fixture.authAccountID = accountID
            return AppModel()
        }

        let failedSave = try setup()
        await failedSave.refreshMessagingDevices()
        let durableBefore = Fixture.saved
        Fixture.failSave = true
        await failedSave.prepareMessagingDeviceAuthority()
        precondition(Fixture.saved == durableBefore && pending() == nil)
        precondition(Fixture.deviceMutationCalls.isEmpty && Fixture.deviceProofs == 0)
        Fixture.failSave = false
        print("PASS proposal persistence failure prevents passkey proof, publication and UI adoption")

        let lostReply = try setup()
        Fixture.deviceLoseReceipt = true
        await lostReply.prepareMessagingDeviceAuthority()
        precondition(Fixture.deviceMutationCalls.count == 1 && Fixture.deviceProofs == 1)
        let exactChange = Fixture.deviceMutationCalls[0]
        precondition(pending() == exactChange && lostReply.deviceAuthority?.approval_code == nil)
        let relaunched = AppModel()
        await relaunched.refreshMessagingDevices()
        precondition(pending() == nil && relaunched.deviceAuthority?.pending == nil && relaunched.deviceAuthority?.approval_code != nil)
        precondition(Fixture.deviceMutationCalls == [exactChange] && Fixture.deviceProofs == 1)
        print("PASS crash after server success with receipt lost reconciles exact signed roster without republishing")

        let expired = try setup()
        Fixture.deviceRejectMutation = true
        await expired.prepareMessagingDeviceAuthority()
        precondition(pending() != nil && Fixture.deviceRemoteAuthority == nil)
        Fixture.devicePendingExpired = true
        let expiredRelaunch = AppModel()
        await expiredRelaunch.refreshMessagingDevices()
        precondition(pending() == nil && expiredRelaunch.deviceAuthority?.approval_code == nil)
        guard case .object(let durable) = Fixture.saved?.core else { preconditionFailure() }
        precondition(durable["burned_device_version"] == .integer(1))
        precondition(Fixture.deviceMutationCalls.count == 1)
        print("PASS expired unpublished proposal clears only through observation and retains burned allocation state")

        let cancelled = try setup()
        Fixture.authAccountID = nil
        await cancelled.prepareMessagingDeviceAuthority()
        guard let cancelledExact = pending() else { preconditionFailure() }
        precondition(Fixture.deviceMutationCalls.isEmpty && cancelled.deviceAuthority?.approval_code == nil)
        Fixture.authAccountID = accountID
        await cancelled.resumeDeviceAuthorization()
        precondition(Fixture.deviceMutationCalls == [cancelledExact] && pending() == nil)
        print("PASS cancelled passkey proof preserves signed proposal and resumes identical change")
        Fixture.deviceNetworkEnabled = false
    }
}
