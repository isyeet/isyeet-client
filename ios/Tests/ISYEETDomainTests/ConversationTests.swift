import Foundation
import Testing
@testable import ISYEETDomain

private enum ConversationFixture {
    static let now: Int64 = 2_000_000
    static let me = "alice@gmail.com"
    static let bob = "bob@gmail.com"
    static let carol = "carol@gmail.com"
    static let pin = String(repeating: "1", count: 64)
    static let contacts = [bob, carol, "dave@gmail.com"].map { Contact(email: $0, fingerprint: pin, verified: true) }

    static func group(_ digit: String = "a", title: String = "Study group", blocked: Bool = false) -> MessageGroup {
        MessageGroup(id: String(repeating: digit, count: 64), title: title,
                     members: [me, bob, carol].map { .init(email: $0, fingerprint: pin) }, blocked: blocked)
    }

    static func message(sender: String = bob, recipient: String = me, text: String? = "Hello",
                        sent: Int64? = now - 100, expiry: Int64? = nil,
                        group: String? = nil, alert: String? = nil, duplicate: Bool = false,
                        expired: Bool = false, deferred: Bool = false, cover: Bool = false) -> StoredMessage {
        StoredMessage(id: UUID().uuidString, sender: sender, recipient: recipient, text: text,
                      security_alert: alert, duplicate: duplicate,
                      expires_at: expiry ?? sent.map { $0 + 604_800 } ?? now + 100,
                      expired: expired, deferred: deferred, cover: cover, group_id: group,
                      sent_at: sent, received_at: now, sender_fingerprint: pin,
                      status: sender == me && group == nil && recipient != me ? "queued" : "received")
    }

    static func outgoing(to recipient: String, expiry: Int64 = now + 100) -> SendRequest {
        SendRequest(id: UUID().uuidString, recipient: recipient, envelope: "opaque-ciphertext", expires_at: expiry)
    }

    static func snapshot(messages: [StoredMessage] = [], outbox: [SendRequest] = [],
                         groups: [MessageGroup] = [], refs: [OutboxReference] = [], coverIDs: [String] = []) -> Snapshot {
        var traffic = TrafficState()
        traffic.cover_outbox_ids = coverIDs
        return Snapshot(email: me, fingerprint: pin, contacts: contacts, outbox: outbox,
                        messages: messages, groups: groups, outbox_refs: refs, traffic: traffic)
    }
}

@Test func conversationSummariesKeepDirectGroupAndSelfIsolated() throws {
    let f = ConversationFixture.self
    let group = f.group()
    let incoming = f.message(text: "**literal** <html> https://example.com", sent: f.now - 20)
    let outgoing = f.message(sender: f.me, recipient: f.bob, text: "  literal spaces  ", sent: f.now - 5)
    let selfMessage = f.message(sender: f.me, text: "Returned through relay", sent: f.now - 10)
    let grouped = f.message(text: "Group only", sent: f.now - 30, group: group.id)
    let unrelated = f.message(sender: f.bob, recipient: f.carol, text: "Never show", sent: f.now)
    let unknown = f.message(sender: "outsider@gmail.com", text: "Not a contact", sent: f.now)
    let snapshot = try f.snapshot(messages: [incoming, selfMessage, grouped, unrelated, unknown, outgoing], groups: [group]).validated()
    let result = snapshot.conversations(unreadCounts: [f.bob: 1, f.me: 99, group.conversationID: 1], at: f.now)
    #expect(result.map(\.id) == [f.bob, f.me, group.conversationID])
    #expect(result.map(\.kind) == [.direct, .selfMessage, .group])
    #expect(result[0].preview == "  literal spaces  ")
    #expect(result[0].previewSender == f.me)
    #expect(result[0].activityAt == outgoing.sent_at)
    #expect(result[0].latestMessageID == outgoing.id)
    #expect(result[0].unreadCount == 1)
    #expect(result[1].title == "Message yourself")
    #expect(result[1].preview == "Returned through relay")
    #expect(result[1].previewSender == f.me)
    #expect(result[1].unreadCount == 0)
    #expect(result[2].preview == "Group only")
    #expect(result[2].previewSender == f.bob)
    #expect(result[2].unreadCount == 1)
    #expect(!result.contains { $0.id == f.carol || $0.id == "dave@gmail.com" })
}

@Test func conversationSummariesExcludeHiddenExpiredDuplicateAndUnrelatedGroupRecords() {
    let f = ConversationFixture.self
    let group = f.group()
    let records = [
        f.message(text: "Cover must never appear", cover: true),
        f.message(text: "Deferred must never appear", deferred: true),
        f.message(text: "Expired flag", expired: true),
        f.message(text: "Expired boundary", expiry: f.now),
        f.message(text: "Duplicate", duplicate: true),
        f.message(sender: "outsider@gmail.com", text: "Not a group member", group: group.id),
        f.message(recipient: f.carol, text: "Other account's group", group: group.id),
        f.message(text: nil, sent: nil),
    ]
    let result = f.snapshot(messages: records, groups: [group]).conversations(
        unreadCounts: [f.bob: 99, group.conversationID: 99], at: f.now)
    #expect(result.count == 1)
    #expect(result[0].id == group.conversationID)
    #expect(result[0].preview == "No messages yet")
    #expect(result[0].latestMessageID == nil)
    #expect(result[0].previewSender == nil)
    #expect(result[0].activityAt == nil)
    #expect(result[0].unreadCount == 0)
}

@Test func pendingSelfHasNoPlaintextEchoAndGroupCopiesDoNotCreateDirectRows() throws {
    let f = ConversationFixture.self
    let group = f.group()
    let bobLeg = f.outgoing(to: f.bob)
    let carolLeg = f.outgoing(to: f.carol)
    let selfEnvelope = f.outgoing(to: f.me)
    let cover = f.outgoing(to: "dave@gmail.com")
    let logicalID = UUID().uuidString
    let refs = [bobLeg, carolLeg].map {
        OutboxReference(id: $0.id, group_id: group.id, message_id: logicalID, recipient: $0.recipient)
    }
    let snapshot = try f.snapshot(outbox: [bobLeg, carolLeg, selfEnvelope, cover], groups: [group], refs: refs, coverIDs: [cover.id]).validated()
    let result = snapshot.conversations(unreadCounts: [:], at: f.now)
    #expect(Set(result.map(\.id)) == Set([f.me, group.conversationID]))
    let own = try #require(result.first { $0.id == f.me })
    #expect(own.preview == "Awaiting return")
    #expect(own.queuedDescription == "Awaiting return")
    #expect(own.queuedCount == 1)
    #expect(own.latestMessageID == nil && own.activityAt == nil)
    #expect(own.previewSender == nil)
    #expect(!own.preview.contains(selfEnvelope.envelope))
    let groupRow = try #require(result.first { $0.id == group.conversationID })
    #expect(groupRow.queuedCount == 1)
    #expect(groupRow.queuedDescription == "1 message queued")
    #expect(groupRow.preview == "Message queued")
    #expect(groupRow.activityAt == nil)
    let expired = snapshot.conversations(unreadCounts: [:], at: f.now + 100)
    #expect(expired.count == 1 && expired[0].id == group.conversationID)
    #expect(expired[0].queuedCount == 0 && expired[0].preview == "No messages yet")
}

@Test func latestUndatedPreviewNeverBorrowsAnEarlierDateOrReceiptTime() {
    let f = ConversationFixture.self
    let old = f.message(text: "Earlier dated", sent: f.now - 1)
    let undated = f.message(text: "Latest undated", sent: nil)
    let carol = f.message(sender: f.carol, text: "Dated other conversation", sent: f.now - 200)
    let result = f.snapshot(messages: [old, carol, undated]).conversations(unreadCounts: [:], at: f.now)
    #expect(result.map(\.id) == [f.carol, f.bob])
    #expect(result[1].preview == "Latest undated")
    #expect(result[1].activityAt == nil)
    #expect(result[1].latestMessageID == undated.id)
}

@Test func unsafeTextAndSecurityRowsHaveOnlyGenericPreviewsAndNoInventedDate() {
    let f = ConversationFixture.self
    for text in ["emoji🙂", "tab\ttext", "\u{1b}[31m", String(repeating: "x", count: 1025)] {
        let invalid = f.message(text: text)
        let row = f.snapshot(messages: [invalid]).conversations(unreadCounts: [f.bob: 20], at: f.now).first
        #expect(row?.preview == "Security alert: message rejected.")
        #expect(row?.activityAt == nil)
        #expect(row?.previewSender == nil)
        #expect(row?.unreadCount == 0)
    }
    let alert = f.message(text: "Do not trust this text", alert: "Untrusted \u{202e} supplied alert")
    let row = f.snapshot(messages: [alert]).conversations(unreadCounts: [:], at: f.now).first
    #expect(row?.preview == "Security alert: message rejected.")
    #expect(row?.activityAt == nil)
    #expect(row?.previewSender == nil)
}

@Test func emptyGroupsStayVisibleWithDeterministicOrderAndBlockedState() {
    let f = ConversationFixture.self
    let first = f.group("a", title: "Same title", blocked: true)
    let second = f.group("b", title: "Same title")
    let result = f.snapshot(groups: [second, first]).conversations(unreadCounts: [:], at: f.now)
    #expect(result.map(\.id) == [first.conversationID, second.conversationID])
    #expect(result.allSatisfy { $0.kind == .group && $0.activityAt == nil && $0.queuedDescription == nil })
    #expect(result[0].blocked && !result[1].blocked)
}

@Test func orphanedOrAmbiguousGroupReferencesNeverFallBackToDirectConversations() {
    let f = ConversationFixture.self
    let group = f.group()
    let request = f.outgoing(to: f.bob)
    let id = UUID().uuidString
    for refs in [
        [OutboxReference(id: request.id, group_id: String(repeating: "c", count: 64), message_id: id, recipient: f.bob)],
        [OutboxReference(id: request.id, group_id: group.id, message_id: id, recipient: f.carol)],
        Array(repeating: OutboxReference(id: request.id, group_id: group.id, message_id: id, recipient: f.bob), count: 2),
    ] {
        let result = f.snapshot(outbox: [request], groups: [group], refs: refs).conversations(unreadCounts: [:], at: f.now)
        #expect(result.count == 1 && result[0].id == group.conversationID)
        #expect(result[0].queuedCount == 0)
    }
}

@Test func directQueuedAndExistingSelfHistoryUseActualRecordsOnly() throws {
    let f = ConversationFixture.self
    let direct = f.outgoing(to: f.bob)
    let selfEnvelope = f.outgoing(to: f.me)
    let selfRecord = f.message(sender: f.me, text: "Earlier returned text", sent: f.now - 50)
    let result = f.snapshot(messages: [selfRecord], outbox: [direct, selfEnvelope]).conversations(unreadCounts: [:], at: f.now)
    let own = try #require(result.first { $0.id == f.me })
    #expect(own.preview == "Earlier returned text")
    #expect(own.previewSender == f.me)
    #expect(own.activityAt == selfRecord.sent_at)
    #expect(own.queuedDescription == "Awaiting return")
    let bob = try #require(result.first { $0.id == f.bob })
    #expect(bob.preview == "Message queued" && bob.activityAt == nil)
    #expect(bob.queuedCount == 1)
}

@Test func peerWrittenYouPrefixNeverChangesTrustedPreviewAuthor() throws {
    let f = ConversationFixture.self
    let incoming = f.message(text: "You: hello")
    let outgoing = f.message(sender: f.me, recipient: f.bob, text: "You: hello")
    let fromPeer = try #require(f.snapshot(messages: [incoming]).conversations(unreadCounts: [:], at: f.now).first)
    let fromSelf = try #require(f.snapshot(messages: [outgoing]).conversations(unreadCounts: [:], at: f.now).first)
    #expect(fromPeer.preview == "You: hello")
    #expect(fromSelf.preview == fromPeer.preview)
    #expect(fromPeer.previewSender == f.bob)
    #expect(fromSelf.previewSender == f.me)
    #expect(fromPeer.previewSender != fromSelf.previewSender)
}
