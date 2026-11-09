import Foundation
import Testing
@testable import ISYEETDomain

@Test func everySingleByteIsValidatedBeforeDecoding() throws {
    for byte in UInt8.min...UInt8.max {
        if (0x20...0x7e).contains(byte) {
            #expect(try MessageSafety.decode(Data([byte])).utf8.first == byte)
        } else {
            #expect(throws: SafetyError.invalidText) { try MessageSafety.decode(Data([byte])) }
        }
    }
}

@Test func messageBoundsAndHostileSequences() throws {
    try MessageSafety.validate(String(repeating: "A", count: 1024))
    try MessageSafety.validate("**literal** <a href='x'> https://example.com")
    for value in ["", String(repeating: "A", count: 1025), "a\nb", "a\tb", "a\u{0}b", "\u{1b}[31m", "\u{202e}evil", "é", "🙂"] {
        #expect(throws: SafetyError.invalidText) { try MessageSafety.validate(value) }
    }
    for bytes: [UInt8] in [[0xc0, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0x41, 0xff, 0x42]] {
        #expect(throws: SafetyError.invalidText) { try MessageSafety.decode(Data(bytes)) }
    }
}

@Test func usernamesAndPermanentAccountIDsStaySeparate() throws {
    for value in ["alice", "matt_1", String(repeating: "a", count: 24)] {
        #expect(try MessageSafety.canonicalUsername(value) == value)
    }
    for value in ["", "ab", "Matt", "1alice", "@alice", "alice@example.com", "alice-1", "a.b", "éaaa", "a\nb", String(repeating: "a", count: 25)] {
        #expect(throws: SafetyError.invalidUsername) { try MessageSafety.canonicalUsername(value) }
    }
    let accountID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    #expect(try MessageSafety.canonicalAccountID(accountID) == accountID)
    for value in [accountID.uppercased(), "aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa", "aaaaaaaa-aaaa-4aaa-0aaa-aaaaaaaaaaaa", "alice"] {
        #expect(throws: SafetyError.invalidAccountID) { try MessageSafety.canonicalAccountID(value) }
    }
}

@Test func legacyAccountNeverSilentlyChangesIdentity() {
    let old = Data(#"{"version":1,"backend":"https://example.com","email":"alice@example.com","token":"synthetic","expiresAt":1234,"core":{},"registered":true}"#.utf8)
    #expect(throws: SafetyError.legacyAccount) { try JSONDecoder().decode(StoredAccount.self, from: old) }
}

@Test func passkeyBase64URLRejectsNoncanonicalAndUnboundedInput() throws {
    let bytes = Data([0, 1, 255])
    #expect(Data(base64URL: bytes.base64URL) == bytes)
    for value in ["", "A", "AA=", "AA+", "AA/", "AB", "AA\n", String(repeating: "A", count: 32769)] {
        #expect(Data(base64URL: value) == nil)
    }
}

@Test func serverTransportPolicy() throws {
    #expect(try MessageSafety.serverURL("https://messages.example.com").scheme == "https")
    #expect(try MessageSafety.serverURL("http://127.0.0.1:8080", allowLoopbackHTTP: true).port == 8080)
    for value in ["http://messages.example.com", "http://127.0.0.1:8080", "https://user:pass@example.com", "https://example.com?token=x", "https://example.com/#fragment", "https://example.com/api"] {
        #expect(throws: SafetyError.insecureServer) { try MessageSafety.serverURL(value) }
    }
    #expect(throws: SafetyError.insecureServer) { try MessageSafety.serverURL("http://127.0.0.1.evil", allowLoopbackHTTP: true) }
}

@Test func opaqueStatePreservesNumbersAndDictionaryKeys() throws {
    let data = Data(#"{"registration_id":4294967295,"large":18446744073709551615,"nested":{"identity_key":"AA=="},"ok":true,"empty":null}"#.utf8)
    let value = try JSONDecoder().decode(JSONValue.self, from: data)
    #expect(try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(value)) == value)
}


private func unreadMessage(_ index: Int, sender: String = "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: String = "81d1a713-5b97-4257-bfb4-f094a2004296",
                           text: String? = "hello", alert: String? = nil, duplicate: Bool = false,
                           expiresAt: Int64 = 4_000_000_000, expired: Bool = false) -> StoredMessage {
    StoredMessage(id: String(format: "00000000-0000-4000-8000-%012d", index), sender: sender,
                  recipient: recipient, text: text, security_alert: alert, duplicate: duplicate,
                  expires_at: expiresAt, expired: expired)
}

private func unreadSnapshot(_ messages: [StoredMessage]) -> Snapshot {
    Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64), contacts: [], outbox: [], messages: messages)
}

@Test func oldAccountsDoNotInventHistoricalUnreadMessages() throws {
    let old = Data(#"{"version":2,"backend":"https://example.com","username":"me_test","account_id":"81d1a713-5b97-4257-bfb4-f094a2004296","token":"synthetic","expiresAt":1234,"core":{"counter":42},"registered":true}"#.utf8)
    let account = try JSONDecoder().decode(StoredAccount.self, from: old)
    #expect(account.unreadMessageIDs.isEmpty)
    #expect(account.core == .object(["counter": .integer(42)]))
    let snapshot = unreadSnapshot([unreadMessage(1), unreadMessage(2)])
    #expect(UnreadMessages.updatedIDs(account.unreadMessageIDs, snapshot: snapshot, reading: MessageReadContext()).isEmpty)
}

@Test func unreadAndCoreStateRoundTripTogetherWithBounds() throws {
    let message = unreadMessage(1)
    var original = StoredAccount(version: 2, backend: "https://example.com", account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"),
                                 token: "synthetic", expiresAt: 1234, core: .object(["counter": .integer(42)]),
                                 registered: true, unreadMessageIDs: [message.id])
    let decoded = try JSONDecoder().decode(StoredAccount.self, from: JSONEncoder().encode(original))
    #expect(decoded.unreadMessageIDs == [message.id])
    #expect(decoded.core == original.core)
    #expect(decoded.account_id == original.account_id && decoded.registered == original.registered)
    original.unreadMessageIDs = (1...201).map { unreadMessage($0).id }
    let oversized = try JSONEncoder().encode(original)
    #expect(throws: SafetyError.persistence) { try JSONDecoder().decode(StoredAccount.self, from: oversized) }
}

@Test func unreadCountsOnlyNewValidIncomingMessages() throws {
    let historical = unreadMessage(1)
    let arrival = unreadMessage(2)
    let outgoing = unreadMessage(3, sender: "81d1a713-5b97-4257-bfb4-f094a2004296", recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d")
    let rejected = unreadMessage(4, text: nil, alert: "rejected")
    let invalid = unreadMessage(5, text: "bad\ntext")
    let wrongRecipient = unreadMessage(6, recipient: "ee9c5bcd-53b5-4939-b07a-8e021c7b6cfc")
    let duplicate = unreadMessage(7, duplicate: true)
    let snapshot = unreadSnapshot([historical, arrival, outgoing, rejected, invalid, wrongRecipient, duplicate])
    let unread = UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: arrival, reading: MessageReadContext())
    #expect(unread == [arrival.id])
    #expect(UnreadMessages.counts(unread, snapshot: snapshot) == ["0beaac69-d53e-48d2-b5aa-dd405b7f414d": 1])
    for excluded in [outgoing, rejected, invalid, wrongRecipient, duplicate, unreadMessage(999)] {
        #expect(UnreadMessages.updatedIDs(unread, snapshot: snapshot, arrival: excluded, reading: MessageReadContext()) == unread)
    }
    // A repeated decrypt result must not re-add a previously seen message.
    let replay = unreadMessage(2, duplicate: true)
    #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: replay, reading: MessageReadContext()).isEmpty)
    #expect(UnreadMessages.updatedIDs(unread, snapshot: snapshot, arrival: arrival, reading: MessageReadContext()) == unread)
}

@Test func unreadPrunesRetiredRejectedAndDuplicateIDs() throws {
    let oldMessages = (1...200).map { unreadMessage($0) }
    let newMessages = (2...201).map { unreadMessage($0) }
    let updated = UnreadMessages.updatedIDs(oldMessages.map(\.id), snapshot: unreadSnapshot(newMessages),
                                            arrival: newMessages.last, reading: MessageReadContext())
    #expect(updated.count == UnreadMessages.maximumCount)
    #expect(!updated.contains(oldMessages[0].id))
    #expect(updated.contains(newMessages.last!.id))
    let valid = unreadMessage(2)
    let rejected = unreadMessage(3, text: nil, alert: "rejected")
    let snapshot = unreadSnapshot([valid, valid, rejected])
    let pruned = UnreadMessages.updatedIDs([valid.id, valid.id, rejected.id, "invalid"], snapshot: snapshot, reading: MessageReadContext())
    #expect(pruned == [valid.id])
    #expect(UnreadMessages.counts([valid.id, valid.id, rejected.id], snapshot: snapshot) == ["0beaac69-d53e-48d2-b5aa-dd405b7f414d": 1])
}

@Test func onlyActiveUncoveredConversationClearsUnread() throws {
    let alice = unreadMessage(1)
    let bob = unreadMessage(2, sender: "300db02d-b75a-4922-8759-f08a0efa5a40")
    let snapshot = unreadSnapshot([alice, bob])
    let unread = [alice.id, bob.id]
    for context in [MessageReadContext(appActive: false, visibleConversation: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", covered: false),
                    MessageReadContext(appActive: true, visibleConversation: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", covered: true),
                    MessageReadContext(appActive: true, visibleConversation: nil, covered: false)] {
        #expect(UnreadMessages.updatedIDs(unread, snapshot: snapshot, reading: context) == unread)
    }
    let readingAlice = MessageReadContext(appActive: true, visibleConversation: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", covered: false)
    #expect(UnreadMessages.updatedIDs(unread, snapshot: snapshot, reading: readingAlice) == [bob.id])
    #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: alice, reading: readingAlice).isEmpty)
    #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: bob, reading: readingAlice) == [bob.id])
    let readingBob = MessageReadContext(appActive: true, visibleConversation: "300db02d-b75a-4922-8759-f08a0efa5a40", covered: false)
    #expect(UnreadMessages.updatedIDs(unread, snapshot: snapshot, reading: readingBob) == [alice.id])
}

@Test func newIdentityRequiresExplicitAuthenticatedAbsence() throws {
    try AccountRegistration.requireUnregistered(statusCode: 404, body: Data(#"{"error":"not found"}"#.utf8))
    // An existing registration blocks creation regardless of its public payload.
    for body in [Data(), Data(#"{"identity_key":"public-test-data"}"#.utf8)] {
        #expect(throws: SafetyError.identityAlreadyRegistered) {
            try AccountRegistration.requireUnregistered(statusCode: 200, body: body)
        }
    }
    #expect(throws: SafetyError.unauthorized) {
        try AccountRegistration.requireUnregistered(statusCode: 401, body: Data())
    }
    for statusCode in [201, 204, 301, 302, 403, 409, 429, 500, 503] {
        #expect(throws: SafetyError.network) {
            try AccountRegistration.requireUnregistered(statusCode: statusCode, body: Data(#"{"error":"not found"}"#.utf8))
        }
    }
}

@Test func malformedMissingIdentityResponseDoesNotPermitKeyCreation() {
    for body in ["", "null", "{}", "[]", "<html>Not found</html>", #"{"error":false}"#,
                 #"{"error":"other error"}"#, #"{"error":"not found","identity_key":"unexpected"}"#] {
        #expect(throws: SafetyError.invalidResponse) {
            try AccountRegistration.requireUnregistered(statusCode: 404, body: Data(body.utf8))
        }
    }
}

@Test func messageExpiryDecodingFailsClosedForUndatedOrExpiredRecords() throws {
    let old = Data(#"{"id":"00000000-0000-4000-8000-000000000001","sender":"0beaac69-d53e-48d2-b5aa-dd405b7f414d","recipient":"81d1a713-5b97-4257-bfb4-f094a2004296","text":"historical","duplicate":false}"#.utf8)
    let undated = try JSONDecoder().decode(StoredMessage.self, from: old)
    #expect(undated.expires_at == 0 && !undated.expired)
    #expect(!undated.isRetained(at: 100))
    let expired = unreadMessage(2, text: nil, expiresAt: 99, expired: true)
    let decoded = try JSONDecoder().decode(StoredMessage.self, from: JSONEncoder().encode(expired))
    #expect(decoded == expired)
    #expect(decoded.text == nil && decoded.security_alert == nil)
    #expect(!decoded.isRetained(at: 1))
    let oldOutbox = try JSONDecoder().decode(SendRequest.self, from: Data(#"{"id":"00000000-0000-4000-8000-000000000001","recipient":"0beaac69-d53e-48d2-b5aa-dd405b7f414d","envelope":"synthetic"}"#.utf8))
    #expect(oldOutbox.expires_at == 0)
}

@Test func expiredMessagesNeverRenderCountUnreadOrRemainRetryable() throws {
    let now: Int64 = 100
    let live = unreadMessage(1, expiresAt: now + 1)
    let boundary = unreadMessage(2, expiresAt: now)
    let past = unreadMessage(3, expiresAt: now - 1)
    let undated = unreadMessage(4, expiresAt: 0)
    let flagged = unreadMessage(5, expiresAt: now + 1, expired: true)
    let outgoing = unreadMessage(6, sender: "81d1a713-5b97-4257-bfb4-f094a2004296", recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", expiresAt: now)
    let input = [live, boundary, past, undated, flagged, outgoing]
    let outbox = input.map { SendRequest(id: $0.id, recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", envelope: "unchanged", expires_at: $0.expires_at) }
    let snapshot = Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64),
                            contacts: [], outbox: outbox, messages: input)
    let display = try snapshot.validated().retained(at: now)
    #expect(display.messages == [live])
    #expect(display.outbox.map(\.id) == [live.id, flagged.id])
    #expect(display.outbox.allSatisfy { $0.envelope == "unchanged" && $0.expires_at == now + 1 })
    #expect(display.nextExpiry == now + 1)
    let unread = UnreadMessages.updatedIDs(input.map(\.id), snapshot: snapshot, reading: MessageReadContext(), now: now)
    #expect(unread == [live.id])
    #expect(UnreadMessages.counts(input.map(\.id), snapshot: snapshot, now: now) == ["0beaac69-d53e-48d2-b5aa-dd405b7f414d": 1])
    for message in [boundary, past, undated, flagged] {
        #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: message, reading: MessageReadContext(), now: now).isEmpty)
    }
    #expect(snapshot.retained(at: now + 1).messages.isEmpty)
    #expect(snapshot.retained(at: now + 1).outbox.isEmpty)
    #expect(snapshot.retained(at: now + 1).nextExpiry == nil)
    // Local cleanup does not depend on a readable conversation or network auth.
    for context in [MessageReadContext(), MessageReadContext(appActive: true, visibleConversation: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", covered: true)] {
        #expect(UnreadMessages.updatedIDs([boundary.id], snapshot: snapshot, reading: context, now: now).isEmpty)
    }
}

@Test func localExpiryBadgePreservesUnreconciledRemoteHints() {
    #expect(NotificationBadge.count(unread: 0, preservingRemoteHint: true, deliveredHint: true) == 1)
    #expect(NotificationBadge.count(unread: 0, preservingRemoteHint: true, deliveredHint: false) == 0)
    #expect(NotificationBadge.count(unread: 3, preservingRemoteHint: true, deliveredHint: true) == 3)
    #expect(NotificationBadge.count(unread: 0, preservingRemoteHint: false, deliveredHint: true) == 0)
    #expect(NotificationBadge.count(unread: 201, preservingRemoteHint: true, deliveredHint: true) == 200)
}

@Test func contactRemovalBindsExactSavedPinWithoutTrustingDirectory() throws {
    let contact = Contact(account_id: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", username: testUsername("0beaac69-d53e-48d2-b5aa-dd405b7f414d"), fingerprint: String(repeating: "a", count: 64), verified: true)
    let request = ContactRemoval(contact: contact)
    try request.validate(current: contact)
    try request.validate(current: Contact(account_id: contact.account_id, username: testUsername(contact.account_id), fingerprint: contact.fingerprint, verified: false))
    for changed in [nil, Contact(account_id: "300db02d-b75a-4922-8759-f08a0efa5a40", username: testUsername("300db02d-b75a-4922-8759-f08a0efa5a40"), fingerprint: contact.fingerprint, verified: true),
                    Contact(account_id: contact.account_id, username: testUsername(contact.account_id), fingerprint: String(repeating: "b", count: 64), verified: true)] {
        #expect(throws: SafetyError.staleContactVerification) { try request.validate(current: changed) }
    }
}

private func syntheticAccountKeys() -> JSONValue {
    .object(["identity_key": .string("new synthetic public key"), "registration_id": .integer(123),
        "signed_pre_key": .object(["id": .integer(1), "public_key": .string("signed"), "signature": .string("signature")]),
        "kyber_pre_key": .object(["id": .integer(2), "public_key": .string("kyber"), "signature": .string("signature")]),
        "pre_keys": .array([.object(["id": .integer(3), "public_key": .string("prekey")])])])
}

@Test func accountOperationJournalKeepsNarrowActionProofForUncertainReply() throws {
    let op = AccountOperation(username: "alice", actionToken: "synthetic-action-proof", kind: .reenroll, backend: "https://example.com", account_id: "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
        operationID: "00000000-0000-4000-8000-000000000001", expiresAt: 1234,
        expectedGeneration: "00000000-0000-4000-8000-000000000002", expectedFingerprint: String(repeating: "a", count: 64),
        preparedCore: .object(["private": .string("synthetic")]), preparedKeys: syntheticAccountKeys(),
        preparedFingerprint: String(repeating: "b", count: 64))
    _ = try op.validated()
    let encoded = try JSONEncoder().encode(op)
    #expect(try JSONDecoder().decode(AccountOperation.self, from: encoded).validated() == op)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("id_token"))
    guard case let .object(request) = op.request() else { Issue.record("Expected object"); return }
    #expect(request["action_token"] == .string(op.actionToken))
    #expect(request["operation_id"] == .string(op.operationID))
    try op.validateCurrentKeys(syntheticAccountKeys())
    guard case var .object(remaining) = syntheticAccountKeys() else { return }
    remaining["pre_keys"] = .array([])
    try op.validateCurrentKeys(.object(remaining)) // A concurrent claim can consume prekeys.
    for field in ["identity_key", "registration_id", "signed_pre_key", "kyber_pre_key"] {
        var altered = remaining; altered[field] = .string("substitution")
        #expect(throws: SafetyError.accountOperationConflict) { try op.validateCurrentKeys(.object(altered)) }
    }
    for invalidPrekeys: JSONValue in [
        .array([.object(["id": .integer(99), "public_key": .string("unknown")])]),
        .array([.object(["id": .integer(3), "public_key": .string("substitution")])]),
        .array([.object(["id": .integer(3), "public_key": .string("prekey")]), .object(["id": .integer(3), "public_key": .string("prekey")])])
    ] {
        var altered = remaining; altered["pre_keys"] = invalidPrekeys
        #expect(throws: SafetyError.accountOperationConflict) { try op.validateCurrentKeys(.object(altered)) }
    }
    #expect(throws: SafetyError.accountOperationConflict) { try op.validateCurrentKeys(.object(["identity_key": .string("superseding identity")])) }
}

@Test func accountOperationRejectsWrongReceiptAndUnboundState() throws {
    let op = AccountOperation(username: "alice", actionToken: "synthetic-action-proof", kind: .delete, backend: "https://example.com", account_id: "0beaac69-d53e-48d2-b5aa-dd405b7f414d",
        operationID: "00000000-0000-4000-8000-000000000001", expiresAt: 1234,
        expectedGeneration: "00000000-0000-4000-8000-000000000002", expectedFingerprint: nil,
        preparedCore: nil, preparedKeys: nil, preparedFingerprint: nil)
    _ = try op.validated()
    try AccountCompletion(operation_id: op.operationID, account_id: op.account_id, completed: true).validate(op)
    for receipt in [AccountCompletion(operation_id: UUID().uuidString, account_id: op.account_id, completed: true),
                    AccountCompletion(operation_id: op.operationID, account_id: "300db02d-b75a-4922-8759-f08a0efa5a40", completed: true),
                    AccountCompletion(operation_id: op.operationID, account_id: op.account_id, completed: false)] {
        #expect(throws: SafetyError.invalidResponse) { try receipt.validate(op) }
    }
    #expect(throws: SafetyError.invalidResponse) {
        try AccountStateResponse(account_id: "300db02d-b75a-4922-8759-f08a0efa5a40", generation: op.expectedGeneration, identity_fingerprint: nil, server_time: 10).validated(account_id: op.account_id)
    }
    #expect(throws: SafetyError.invalidResponse) {
        try AccountStateResponse(account_id: op.account_id, generation: "invalid", identity_fingerprint: nil, server_time: 10).validated(account_id: op.account_id)
    }
}

@Test func accountGenerationRequiresCanonicalLowercaseUUIDv4() {
    for invalid in ["00000000-0000-1000-8000-000000000001", "00000000-0000-4000-0000-000000000001", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"] {
        #expect(!AccountStateResponse.canonicalGeneration(invalid))
    }
    #expect(AccountStateResponse.canonicalGeneration("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
}

@Test func observedIdentityChangesPersistBoundedlyAndOldAccountsDefaultEmpty() throws {
    let old = Data(#"{"version":2,"backend":"https://example.com","username":"me_test","account_id":"81d1a713-5b97-4257-bfb4-f094a2004296","token":"synthetic","expiresAt":1234,"core":{},"registered":true}"#.utf8)
    var account = try JSONDecoder().decode(StoredAccount.self, from: old)
    #expect(account.contactIdentityChanges.isEmpty)
    account.contactIdentityChanges = ["0beaac69-d53e-48d2-b5aa-dd405b7f414d", "5ff860bf-1190-496c-b188-ab851db691f0"]
    let restored = try JSONDecoder().decode(StoredAccount.self, from: JSONEncoder().encode(account))
    #expect(restored.contactIdentityChanges == account.contactIdentityChanges)
    for invalid in [["Alice@gmail.com"], ["alice+alias@gmail.com"], Array(repeating: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", count: 65)] {
        account.contactIdentityChanges = invalid
        let encoded = try JSONEncoder().encode(account)
        #expect(throws: SafetyError.persistence) { try JSONDecoder().decode(StoredAccount.self, from: encoded) }
    }
}

@Test func selfConversationNeverIncludesOtherContactsOrExpiredMessages() throws {
    let own = "81d1a713-5b97-4257-bfb4-f094a2004296"
    let selfMessage = unreadMessage(101, sender: own, recipient: own, expiresAt: 101)
    let expiredSelf = unreadMessage(102, sender: own, recipient: own, expiresAt: 100)
    let aliceIncoming = unreadMessage(103, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: own, expiresAt: 101)
    let aliceOutgoing = unreadMessage(104, sender: own, recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", expiresAt: 101)
    let unrelated = unreadMessage(105, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: "300db02d-b75a-4922-8759-f08a0efa5a40", expiresAt: 101)
    let snapshot = unreadSnapshot([selfMessage, expiredSelf, aliceIncoming, aliceOutgoing, unrelated])
    #expect(snapshot.messages(in: own, at: 100) == [selfMessage])
    #expect(snapshot.messages(in: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", at: 100) == [aliceIncoming, aliceOutgoing])
    #expect(snapshot.messages(in: "300db02d-b75a-4922-8759-f08a0efa5a40", at: 100).isEmpty)
    #expect(snapshot.messages(in: own, at: 101).isEmpty)
}

@Test func selfRoundTripIsExcludedFromPeerUnreadIndicators() throws {
    let selfMessage = unreadMessage(106, sender: "81d1a713-5b97-4257-bfb4-f094a2004296", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", expiresAt: 101)
    let peer = unreadMessage(107, expiresAt: 101)
    let snapshot = unreadSnapshot([selfMessage, peer])
    #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: selfMessage, reading: MessageReadContext(), now: 100).isEmpty)
    #expect(UnreadMessages.counts([selfMessage.id, peer.id], snapshot: snapshot, now: 100) == ["0beaac69-d53e-48d2-b5aa-dd405b7f414d": 1])
    #expect(UnreadMessages.updatedIDs([peer.id], snapshot: snapshot, arrival: selfMessage, reading: MessageReadContext(), now: 100) == [peer.id])
}

private func sampleGroup(_ digit: String = "1", blocked: Bool = false) -> MessageGroup {
    MessageGroup(id: String(repeating: digit, count: 64), title: "ASCII **group**",
                 members: [.init(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", fingerprint: String(repeating: "a", count: 64)),
                           .init(account_id: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", fingerprint: String(repeating: "b", count: 64))], blocked: blocked)
}

@Test func oldSnapshotsAndMessagesDoNotInventMetadataOrGroups() throws {
    let json = #"{"account_id":"81d1a713-5b97-4257-bfb4-f094a2004296","username":"me_test","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","contacts":[],"outbox":[],"messages":[]}"#
    let snapshot = try JSONDecoder().decode(Snapshot.self, from: Data(json.utf8))
    #expect(snapshot.groups.isEmpty && snapshot.outbox_refs.isEmpty && snapshot.pending_group_senders.isEmpty)
    #expect(snapshot.resolved_message_ids.isEmpty && snapshot.nextExpiry == nil)
    let message = unreadMessage(201)
    let restored = try JSONDecoder().decode(StoredMessage.self, from: JSONEncoder().encode(message))
    #expect(restored.authenticatedSentAt == nil && restored.received_at == nil && restored.historicalFingerprint == nil)
    #expect(restored.status == nil && restored.deliveryDescription == "Not recorded" && !restored.deferred)
}

@Test func groupSyntaxAndRosterBoundsFailClosed() throws {
    try MessageGroup.validateTitle(String(repeating: "A", count: 48))
    for title in ["", String(repeating: "A", count: 49), "line\nbreak", "tab\t", "\u{1b}[31m", "Grüppe", "\u{202e}spoof"] {
        #expect(throws: SafetyError.invalidGroup) { try MessageGroup.validateTitle(title) }
    }
    let group = sampleGroup()
    _ = try Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64), contacts: [], outbox: [], messages: [], groups: [group]).validated()
    for members in [Array(group.members.prefix(1)), [group.members[0], group.members[0]],
                    [group.members[1], .init(account_id: "300db02d-b75a-4922-8759-f08a0efa5a40", fingerprint: String(repeating: "c", count: 64))],
                    [.init(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", fingerprint: String(repeating: "c", count: 64)), group.members[1]]] {
        let invalid = MessageGroup(id: group.id, title: group.title, members: members, blocked: false)
        #expect(throws: SafetyError.invalidResponse) {
            try Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64), contacts: [], outbox: [], messages: [], groups: [invalid]).validated()
        }
    }
}

@Test func groupsHaveSeparateHistoryAndUnreadContextsFromSameSender() throws {
    let group = sampleGroup(), other = sampleGroup("2")
    let direct = unreadMessage(210, expiresAt: 700_100)
    let incoming = StoredMessage(id: unreadMessage(211).id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", text: "group text",
                                 security_alert: nil, duplicate: false, expires_at: 700_100, group_id: group.id,
                                 sent_at: 95_300, received_at: 95_400, sender_fingerprint: String(repeating: "b", count: 64), status: "received")
    let outgoing = StoredMessage(id: unreadMessage(212).id, sender: "81d1a713-5b97-4257-bfb4-f094a2004296", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", text: "outgoing group",
                                 security_alert: nil, duplicate: false, expires_at: 700_100, group_id: group.id, status: "queued", accepted_count: 0, recipient_count: 1)
    let snapshot = try Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64), contacts: [], outbox: [],
                                messages: [direct, incoming, outgoing], groups: [group, other]).validated()
    #expect(snapshot.messages(in: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", at: 100) == [direct])
    #expect(snapshot.messages(in: "81d1a713-5b97-4257-bfb4-f094a2004296", at: 100).isEmpty)
    #expect(snapshot.messages(in: group.conversationID, at: 100) == [incoming, outgoing])
    #expect(snapshot.messages(in: other.conversationID, at: 100).isEmpty)
    #expect(UnreadMessages.counts([direct.id, incoming.id, outgoing.id], snapshot: snapshot, now: 100) == ["0beaac69-d53e-48d2-b5aa-dd405b7f414d": 1, group.conversationID: 1])
    let readingGroup = MessageReadContext(appActive: true, visibleConversation: group.conversationID)
    #expect(UnreadMessages.updatedIDs([direct.id, incoming.id], snapshot: snapshot, reading: readingGroup, now: 100) == [direct.id])
    let readingDirect = MessageReadContext(appActive: true, visibleConversation: "0beaac69-d53e-48d2-b5aa-dd405b7f414d")
    #expect(UnreadMessages.updatedIDs([direct.id, incoming.id], snapshot: snapshot, reading: readingDirect, now: 100) == [incoming.id])
    let detailsCoverGroup = MessageReadContext(appActive: true, visibleConversation: group.conversationID, covered: true)
    #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: incoming, reading: detailsCoverGroup, now: 100) == [incoming.id])
    #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrival: outgoing, reading: MessageReadContext(), now: 100).isEmpty)
}

@Test func detailsResolveLiveIDsAndNeverInventAuthenticationForRejectedRecords() throws {
    let original = StoredMessage(id: unreadMessage(220).id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", text: "private ASCII",
                                 security_alert: nil, duplicate: false, expires_at: 700_000, sent_at: 95_200, received_at: 96_000,
                                 sender_fingerprint: String(repeating: "b", count: 64), status: "received")
    let selection = MessageSelection(id: original.id)
    let live = unreadSnapshot([original])
    #expect(live.message(id: selection.id, at: 699_999)?.authenticatedSentAt == 95_200)
    #expect(live.message(id: selection.id, at: 700_000) == nil)
    #expect(unreadSnapshot([]).message(id: selection.id, at: 100) == nil)
    let rejected = StoredMessage(id: unreadMessage(221).id, sender: original.sender, recipient: original.recipient, text: nil,
                                 security_alert: "untrusted upstream alert", duplicate: false, expires_at: 700_000,
                                 sent_at: 95_200, sender_fingerprint: String(repeating: "b", count: 64))
    #expect(rejected.authenticatedSentAt == nil && rejected.historicalFingerprint == nil)
    #expect(unreadSnapshot([rejected]).message(id: rejected.id, at: 100) != nil)
    let deferred = StoredMessage(id: unreadMessage(222).id, sender: original.sender, recipient: original.recipient, text: nil,
                                 security_alert: nil, duplicate: false, expires_at: 700_000, deferred: true)
    #expect(!deferred.isRetained(at: 100))
    #expect(UnreadMessages.updatedIDs([], snapshot: unreadSnapshot([deferred]), arrival: deferred, reading: MessageReadContext(), now: 100).isEmpty)
}

@Test func locallyResolvedGroupMessagesAreUnreadWithoutInventingHistoricUnread() throws {
    let group = sampleGroup()
    let historical = unreadMessage(230, expiresAt: 1000)
    let resolved = StoredMessage(id: unreadMessage(231).id, sender: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296", text: "resolved",
                                 security_alert: nil, duplicate: false, expires_at: 1000, group_id: group.id)
    let snapshot = Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64), contacts: [], outbox: [],
                            messages: [historical, resolved], groups: [group], resolved_message_ids: [resolved.id], next_expiry: 500)
    let ids = UnreadMessages.updatedIDs([], snapshot: snapshot, arrivals: [resolved], reading: MessageReadContext(), now: 100)
    #expect(ids == [resolved.id])
    #expect(UnreadMessages.counts(ids, snapshot: snapshot, now: 100) == [group.conversationID: 1])
    #expect(snapshot.nextExpiry == 500)
    #expect(UnreadMessages.updatedIDs([], snapshot: snapshot, arrivals: [resolved], reading: MessageReadContext(), now: 1000).isEmpty)
}

@Test func relayAcceptanceMetadataNeverMeansDeliveredOrRead() throws {
    let statuses = ["queued", "partially_accepted", "relay_accepted", "received", "cancelled"]
    for status in statuses {
        let message = StoredMessage(id: unreadMessage(240).id, sender: "81d1a713-5b97-4257-bfb4-f094a2004296", recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", text: "test",
                                    security_alert: nil, duplicate: false, expires_at: 700_000, status: status)
        #expect(!message.deliveryDescription.lowercased().contains("delivered"))
        #expect(!message.deliveryDescription.lowercased().contains("read"))
    }
    let unknown = StoredMessage(id: unreadMessage(241).id, sender: "81d1a713-5b97-4257-bfb4-f094a2004296", recipient: "0beaac69-d53e-48d2-b5aa-dd405b7f414d", text: "test",
                               security_alert: nil, duplicate: false, expires_at: 700_000, status: "attacker status")
    #expect(throws: SafetyError.invalidResponse) { try unreadSnapshot([unknown]).validated() }
}

@Test func coverCadenceIgnoresDemandAndNeverCatchesUp() {
    let start = ContinuousClock().now
    var cadence = CoverCadence()
    cadence.arm(now: start, delay: .seconds(30))
    let original = cadence.deadline
    // Repeated user activity cannot accelerate or postpone an armed slot.
    cadence.arm(now: start.advanced(by: .seconds(10)), delay: .seconds(15))
    cadence.arm(now: start.advanced(by: .seconds(20)), delay: .seconds(45))
    #expect(cadence.deadline == original)
    let early = cadence.consume(now: start.advanced(by: .seconds(29)), nextDelay: .seconds(15))
    #expect(!early)
    let late = cadence.consume(now: start.advanced(by: .seconds(100)), nextDelay: .seconds(45))
    #expect(late)
    #expect(cadence.deadline == start.advanced(by: .seconds(145)))
    let catchUp = cadence.consume(now: start.advanced(by: .seconds(100)), nextDelay: .seconds(15))
    #expect(!catchUp)
    cadence.stop()
    cadence.arm(now: start.advanced(by: .seconds(1_000)), delay: .seconds(30))
    let resumed = cadence.consume(now: start.advanced(by: .seconds(1_001)), nextDelay: .seconds(15))
    #expect(!resumed)
    #expect(cadence.deadline == start.advanced(by: .seconds(1_030)))
}

@Test func encryptedRequestsAlwaysHaveSameHTTPBodyLength() throws {
    let longestAccountID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    for account_id in ["75f4499b-5920-4d38-b057-e967e297590a", longestAccountID] {
        let request = SendRequest(id: UUID().uuidString.lowercased(), recipient: account_id,
                                  envelope: Data(repeating: 0xff, count: 8192).base64EncodedString(), expires_at: 1_800_000_000)
        let bytes = try MessageTransport.paddedBody(request)
        #expect(bytes.count == 12_288)
        #expect(bytes.last == 0x20)
        let decoded = try JSONDecoder().decode(SendRequest.self, from: bytes)
        #expect(decoded.envelope == request.envelope && decoded.recipient == account_id && decoded.id == request.id)
    }
    let oversized = SendRequest(id: UUID().uuidString, recipient: "75f4499b-5920-4d38-b057-e967e297590a", envelope: String(repeating: "x", count: 13_000), expires_at: 1)
    #expect(throws: SafetyError.invalidResponse) { try MessageTransport.paddedBody(oversized) }
}

@Test func coversNeverBecomeVisibleOrUnreadEvenWithInvalidDisplayPayload() throws {
    let cover = StoredMessage(id: UUID().uuidString.lowercased(), sender: "75f4499b-5920-4d38-b057-e967e297590a", recipient: "81d1a713-5b97-4257-bfb4-f094a2004296",
                              text: "This must never be rendered", security_alert: "Nor this", duplicate: false,
                              expires_at: 200, cover: true)
    let snapshot = Snapshot(account_id: "81d1a713-5b97-4257-bfb4-f094a2004296", username: testUsername("81d1a713-5b97-4257-bfb4-f094a2004296"), fingerprint: String(repeating: "a", count: 64), contacts: [], outbox: [], messages: [cover])
    #expect(snapshot.message(id: cover.id, at: 100) == nil)
    #expect(snapshot.messages(in: "75f4499b-5920-4d38-b057-e967e297590a", at: 100).isEmpty)
    #expect(UnreadMessages.updatedIDs([cover.id], snapshot: snapshot, arrival: cover, reading: MessageReadContext(), now: 100).isEmpty)
    #expect(snapshot.retained(at: 100).messages.isEmpty)
}

@Test func legacySnapshotDefaultsToNotificationsWithoutCoverData() throws {
    let data = Data("""
    {"account_id":"81d1a713-5b97-4257-bfb4-f094a2004296","username":"me_test","fingerprint":"\(String(repeating: "a", count: 64))","contacts":[],"outbox":[],"messages":[]}
    """.utf8)
    let decoded = try JSONDecoder().decode(Snapshot.self, from: data).validated()
    #expect(!decoded.traffic.enabled && decoded.traffic.cover_outbox_ids.isEmpty)
    #expect(decoded.traffic.eligible_contacts.isEmpty && decoded.traffic.remaining_budget == 4096)
    let malformed = Data("""
    {"cover":true,"notifications_resume_at":0,"server_time":1800000000}
    """.utf8)
    #expect(throws: SafetyError.invalidResponse) {
        try JSONDecoder().decode(TrafficModeResponse.self, from: malformed).validated()
    }
}


@Test func coverRoundTripUsesConservativeMonotonicCeilingAndBound() throws {
    let start = ContinuousClock().now
    #expect(try TrafficClock.elapsedSeconds(from: start, to: start) == 0)
    #expect(try TrafficClock.elapsedSeconds(from: start, to: start.advanced(by: .nanoseconds(1))) == 1)
    #expect(try TrafficClock.elapsedSeconds(from: start, to: start.advanced(by: .milliseconds(1_001))) == 2)
    #expect(try TrafficClock.elapsedSeconds(from: start, to: start.advanced(by: .seconds(60))) == 60)
    #expect(throws: SafetyError.trafficUnavailable) {
        try TrafficClock.elapsedSeconds(from: start, to: start.advanced(by: .milliseconds(60_001)))
    }
    #expect(throws: SafetyError.trafficUnavailable) {
        try TrafficClock.elapsedSeconds(from: start, to: start.advanced(by: .seconds(-1)))
    }
}

@Test func serviceBuildNamesCannotConcealAnotherOrigin() throws {
    for (name, url) in [("production", "https://api.isyeet.io"), ("staging", "https://api-staging.isyeet.io")] {
        #expect(try ServiceEnvironment(name: name, server: URL(string: url)!, allowLocal: false).rawValue == name)
    }
    for url in ["https://api-staging.isyeet.io", "http://api.isyeet.io", "https://api.isyeet.io.evil", "https://api.isyeet.io:443", "https://api.isyeet.io/"] {
        #expect(throws: SafetyError.configuration) { try ServiceEnvironment(name: "production", server: URL(string: url)!, allowLocal: false) }
    }
    #expect(throws: SafetyError.configuration) { try ServiceEnvironment(name: "local", server: URL(string: "http://127.0.0.1:18081")!, allowLocal: false) }
    #expect(try ServiceEnvironment(name: "local", server: URL(string: "http://127.0.0.1:18081")!, allowLocal: true) == .local)
}

@Test func accountAndOperationStorageIsOriginBoundWithoutStagingMigration() throws {
    let staging = try AccountStorageScope(server: URL(string: "https://api-staging.isyeet.io")!)
    let production = try AccountStorageScope(server: URL(string: "https://api.isyeet.io")!)
    #expect(staging.service == "com.isyeet.app.account.v1")
    #expect(production.service != staging.service)
    for url in ["https://api.isyeet.io.evil", "http://127.0.0.1:18081", "http://127.0.0.1:18082"] {
        #expect(try AccountStorageScope(server: URL(string: url)!).service != production.service)
    }
    try production.validate(backend: production.backend)
    #expect(throws: SafetyError.accountMismatch) { try production.validate(backend: staging.backend) }
    #expect(throws: SafetyError.accountMismatch) { try staging.validate(backend: production.backend) }
}

@Test func keyMaintenanceDecodingNeverInventsNewRegistrationPermission() throws {
    let legacy = try JSONDecoder().decode(KeyMaintenanceState.self, from: Data(#"{"pending":null,"next_check_at":0}"#.utf8))
    #expect(!legacy.initial_upload_pending && legacy.pending == nil)
    let fresh = KeyMaintenanceState(next_check_at: 0, initial_upload_pending: true)
    #expect(try JSONDecoder().decode(KeyMaintenanceState.self, from: JSONEncoder().encode(fresh)).initial_upload_pending)
}

@Test func nativePasskeyWireOptionsKeepAccountAndCredentialIdentifiersSeparate() throws {
    let data = Data(#"{"challenge_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","account_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","username":"alice","public_key":{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"api-staging.isyeet.io","name":"ISYEET"},"user":{"id":"u7u7u7u7S7uLu7u7u7u7uw","name":"alice","displayName":"alice"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"excludeCredentials":[{"type":"public-key","id":"AQID"}],"authenticatorSelection":{"residentKey":"required","userVerification":"required"}}}"#.utf8)
    let decoded = try JSONDecoder().decode(PasskeyChallenge.self, from: data)
    #expect(decoded.public_key.rp?.id == "api-staging.isyeet.io")
    #expect(decoded.username == "alice")
    #expect(decoded.public_key.user?.name == decoded.username)
    #expect(decoded.public_key.excludeCredentials?.first?.id == "AQID")
    #expect(decoded.account_id != decoded.public_key.user?.id)
    #expect(decoded.public_key.pubKeyCredParams?.first?.alg == -7)
}

@Test func accountUsernameCannotSilentlyBecomeAnotherIdentity() throws {
    let id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    #expect(try DirectoryAccount(account_id: id, username: "alice").validated().account_id == id)
    for invalid in [DirectoryAccount(account_id: "alice", username: "alice"),
                    DirectoryAccount(account_id: id, username: "@alice"),
                    DirectoryAccount(account_id: id.uppercased(), username: "alice")] {
        #expect(throws: SafetyError.invalidResponse) { try invalid.validated() }
    }
}
