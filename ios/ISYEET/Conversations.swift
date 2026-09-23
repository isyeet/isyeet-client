import SwiftUI

struct ConversationView: View {
    @ObservedObject var model: AppModel
    @Environment(\.appearance) private var appearance
    let email: String
    @State private var text = ""
    @State private var showingContact = false
    @State private var showingFaces = false
    @State private var selectedMessage: MessageSelection?

    private var contact: Contact? { model.snapshot?.contacts.first { $0.email == email } }
    private var isSelfConversation: Bool { model.snapshot?.email == email }
    private var title: String { isSelfConversation ? "Message yourself" : email }
    private var pendingSelfCount: Int { model.snapshot?.outbox.filter { $0.recipient == email }.count ?? 0 }
    private var identityChanged: Bool { model.pendingIdentityChanges.contains(email) }
    private var verified: Bool { isSelfConversation || contact?.verified == true && !identityChanged }
    private var canSend: Bool {
        verified && !model.busy && !text.isEmpty && !model.needsAuthentication && model.fatalError == nil
            && !showingContact && !showingFaces && selectedMessage == nil
    }

    var body: some View {
        VStack(spacing: 0) {
            NewMessageNotice(model: model)
            if model.snapshot != nil, isSelfConversation || contact != nil {
                if !verified {
                    VStack(alignment: .leading, spacing: 8) {
                        Label(identityChanged ? "This contact's identity changed" : "Verify this contact to start messaging", systemImage: "exclamationmark.shield")
                            .font(appearance.font(.subheadline).weight(.semibold))
                        Text(identityChanged ? "Do not trust this new key yet. Remove the old contact, add them again, and compare their new fingerprint outside ISYEET. Existing affected groups stay blocked." : "Compare fingerprints through a trusted channel outside ISYEET.")
                            .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                        Button(identityChanged ? "Review identity" : "Verify contact", action: showContact)
                            .font(appearance.font(.subheadline).weight(.semibold))
                    }
                    .foregroundStyle(appearance.warning)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding().background(appearance.surface)
                }
                if isSelfConversation {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Your text appears after an encrypted round trip through the relay.")
                        if pendingSelfCount > 0 {
                            Text("Queued on this device: \(pendingSelfCount)").foregroundStyle(appearance.warning)
                        } else if model.checkingInbox {
                            Text("Checking for returned messages…")
                        }
                    }
                    .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.vertical, 12).background(appearance.surface)
                }
                MessageTranscript(model: model, conversationID: email, selfConversation: isSelfConversation) { selectedMessage = $0 }
                composer
            } else {
                ContentUnavailableView("Conversation unavailable", systemImage: "lock")
            }
        }
        .font(appearance.font(.body)).foregroundStyle(appearance.primary).background(appearance.background)
        .onAppear { model.conversationDidAppear(email) }
        .onDisappear { model.conversationDidDisappear(email) }
        .sheet(isPresented: $showingContact, onDismiss: { model.setPresentationCovered("contact-details", covered: false) }) {
            NavigationStack {
                ContactDetailsView(model: model, email: email)
                    .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { showingContact = false } } }
            }
        }
        .sheet(item: $selectedMessage, onDismiss: { model.setPresentationCovered("message-details", covered: false) }) { selection in
            MessageDetailsView(model: model, selection: selection)
        }
        .sheet(isPresented: $showingFaces, onDismiss: { model.setPresentationCovered("ascii-faces", covered: false) }) {
            ASCIIFacesPicker(draft: $text, enabled: verified && !model.busy && !model.needsAuthentication && model.fatalError == nil)
        }
        .onChange(of: contact?.fingerprint) { previous, current in
            // A committed replacement clears unsent composer text as well as
            // core history, even when it happened in the contact details sheet.
            if previous != current { text = ""; showingFaces = false }
        }
        .onChange(of: model.inboxNavigationSequence) { _, _ in selectedMessage = nil; showingContact = false; showingFaces = false }
        .navigationTitle(Text(verbatim: title)).navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(appearance.background, for: .navigationBar).toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .principal) {
                ConversationHeading(title: title, subtitle: isSelfConversation ? "Encrypted delivery test" : (verified ? "Verified contact" : "Verification required"))
            }
            if !isSelfConversation, contact != nil {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Contact details", systemImage: "info.circle", action: showContact)
                }
            }
        }
    }

    private func showContact() {
        model.setPresentationCovered("contact-details", covered: true)
        showingContact = true
    }

    private var composer: some View {
        VStack(spacing: 8) {
            if model.trafficMode == .cover {
                Text("Queued messages wait for the next foreground sending slot.").font(appearance.font(.caption)).foregroundStyle(appearance.secondary)
            }
            HStack(alignment: .center, spacing: 12) {
                if appearance == .terminal { Text(">").font(appearance.font(.headline)).foregroundStyle(appearance.accent).accessibilityHidden(true) }
                TextField("ASCII text", text: $text, prompt: Text("ASCII text").foregroundStyle(appearance.secondary))
                    .font(appearance.font(.body)).keyboardType(.asciiCapable).autocorrectionDisabled().textInputAutocapitalization(.never)
                    .submitLabel(.send).onSubmit { send() }
                    .disabled(!verified || showingContact || showingFaces || selectedMessage != nil)
                    .padding(.horizontal, 12).frame(minHeight: 44)
                    .background(appearance.background, in: RoundedRectangle(cornerRadius: appearance == .terminal ? 2 : 20))
                    .overlay { RoundedRectangle(cornerRadius: appearance == .terminal ? 2 : 20).strokeBorder(appearance.secondary.opacity(0.35)) }
                Button("Send", action: send).font(appearance.font(.headline))
                    .foregroundStyle(canSend ? appearance.accent : appearance.secondary).frame(minHeight: 44).disabled(!canSend)
            }
            ComposerFooter(text: text, facesEnabled: verified && !model.busy && !model.needsAuthentication && model.fatalError == nil && !showingContact && selectedMessage == nil) {
                model.setPresentationCovered("ascii-faces", covered: true)
                showingFaces = true
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12).background(appearance.surface)
    }

    private func send() {
        guard canSend else { return }
        let submitted = text
        Task { if await model.send(text: submitted, recipient: email), text == submitted { text = "" } }
    }
}

// Navigation content, so the Contacts tab and a conversation sheet use exactly
// the same verification workflow. Merely viewing it never marks messages read.
struct ContactDetailsView: View {
    @ObservedObject var model: AppModel
    let email: String
    var openConversation: (() -> Void)? = nil
    @Environment(\.appearance) private var appearance
    @State private var fingerprint = ""
    @State private var removal: ContactRemoval?
    @State private var feedback: String?
    @State private var coverageID = "contact-management:" + UUID().uuidString

    private var contact: Contact? { model.snapshot?.contacts.first { $0.email == email } }
    private var identityChanged: Bool { model.pendingIdentityChanges.contains(email) }
    private var available: Bool { !model.busy && !model.needsAuthentication && model.fatalError == nil && removal == nil }
    private var removalAvailable: Bool { !model.busy && model.fatalError == nil && removal == nil }

    var body: some View {
        Form {
            if let contact {
                Section {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(verbatim: email).font(appearance.font(.headline)).textSelection(.enabled)
                        Label(identityChanged ? "KEY CHANGE — STOP AND VERIFY" : (contact.verified ? "Verified on this device" : "Not verified"),
                              systemImage: identityChanged || !contact.verified ? "exclamationmark.shield" : "checkmark.shield")
                            .font(appearance.font(.subheadline)).foregroundStyle(identityChanged || !contact.verified ? appearance.warning : appearance.accent)
                    }.padding(.vertical, 6)
                    if let openConversation {
                        Button("Message", systemImage: "bubble.left") { openConversation() }
                            .disabled(!contact.verified || identityChanged || model.fatalError != nil || removal != nil)
                    }
                }.listRowBackground(appearance.surface)
                if identityChanged {
                    Section("Identity changed") {
                        Label("KEY CHANGED", systemImage: "exclamationmark.triangle.fill")
                            .font(appearance.font(.title2).bold()).foregroundStyle(appearance.warning)
                        Text("This may be a lost-device re-enrollment or an impersonation attempt. Google sign-in does not prove the new encryption identity. Sending is blocked. Remove the old contact, add them again, then independently compare the new fingerprint outside ISYEET. Existing affected groups cannot be reused.")
                            .foregroundStyle(appearance.warning)
                    }.listRowBackground(appearance.surface)
                }
                if !contact.verified && !identityChanged {
                    Section("Verify this person") {
                        Text("Obtain their full fingerprint through a trusted channel outside ISYEET. Enter that independently obtained value below.")
                            .font(appearance.font(.footnote))
                        TextField("Their 64-character fingerprint", text: $fingerprint,
                                  prompt: Text("Their 64-character fingerprint").foregroundStyle(appearance.secondary), axis: .vertical)
                            .font(.system(.body, design: .monospaced)).textInputAutocapitalization(.never)
                            .autocorrectionDisabled().keyboardType(.asciiCapable).disabled(!available)
                        Button("Verify identity", action: verify)
                            .disabled(!available || fingerprint.isEmpty)
                        if let feedback { Text(verbatim: feedback).font(appearance.font(.footnote)).foregroundStyle(appearance.warning) }
                    }.listRowBackground(appearance.surface)
                }
                Section(contact.verified ? "Saved verified fingerprint" : "Saved unverified fingerprint") {
                    Text(verbatim: contact.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    Text("Compare the full fingerprint outside ISYEET. This saved value is never filled into the verification input for you.")
                        .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                }.listRowBackground(appearance.surface)
                Section("Remove contact") {
                    Text("Removal deletes this contact's direct history and unsent messages, stops new relay deliveries after synchronization, and permanently blocks existing groups that include them. Other contacts and your own identity stay unchanged.")
                        .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                    Button("Remove contact", role: .destructive) {
                        guard removalAvailable else { return }
                        model.setPresentationCovered("contact-remove", covered: true)
                        removal = ContactRemoval(contact: contact)
                    }.disabled(!removalAvailable)
                }.listRowBackground(appearance.surface)
            } else {
                Text("This contact is unavailable.").listRowBackground(appearance.surface)
            }
        }
        .font(appearance.font(.body)).foregroundStyle(appearance.primary)
        .scrollContentBackground(.hidden).background(appearance.background)
        .navigationTitle("Contact details").navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(appearance.background, for: .navigationBar).toolbarBackground(.visible, for: .navigationBar)
        .onAppear { model.setPresentationCovered(coverageID, covered: true) }
        .onDisappear { model.setPresentationCovered(coverageID, covered: false) }
        .sheet(item: $removal, onDismiss: { model.setPresentationCovered("contact-remove", covered: false) }) { request in
            RemoveContactView(model: model, request: request)
        }
        .onChange(of: model.inboxNavigationSequence) { _, _ in removal = nil }
    }

    private func verify() {
        guard available else { return }
        let expected = fingerprint.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "").lowercased()
        guard MessageSafety.validFingerprint(expected) else { feedback = SafetyError.invalidFingerprint.errorDescription; return }
        feedback = nil
        Task {
            await model.verifyContact(email: email, fingerprint: expected)
            if contact?.verified == true && contact?.fingerprint == expected { fingerprint = "" }
            else { feedback = "Verification was not saved. Check the full fingerprint with this person outside ISYEET." }
        }
    }
}

struct GroupConversationView: View {
    @ObservedObject var model: AppModel
    let groupID: String
    @Environment(\.appearance) private var appearance
    @State private var text = ""
    @State private var showingGroup = false
    @State private var showingFaces = false
    @State private var selectedMessage: MessageSelection?

    private var group: MessageGroup? { model.snapshot?.groups.first { $0.id == groupID } }
    private var conversationID: String { "group:" + groupID }
    private var canSend: Bool {
        !model.busy && model.fatalError == nil && !model.needsAuthentication && !model.groupIsBlocked(groupID)
            && !text.isEmpty && !showingGroup && !showingFaces && selectedMessage == nil
    }

    var body: some View {
        VStack(spacing: 0) {
            NewMessageNotice(model: model)
            if group != nil {
                if model.groupIsBlocked(groupID) {
                    Label("An identity changed. Verify the new identity and create a new group; this group's queued sends are cancelled.", systemImage: "exclamationmark.shield")
                        .font(appearance.font(.footnote)).foregroundStyle(appearance.warning)
                        .frame(maxWidth: .infinity, alignment: .leading).padding().background(appearance.surface)
                }
                MessageTranscript(model: model, conversationID: conversationID, group: true) { selectedMessage = $0 }
                VStack(spacing: 8) {
                    if model.trafficMode == .cover {
                        Text("Queued messages use one foreground slot per recipient.").font(appearance.font(.caption)).foregroundStyle(appearance.secondary)
                    }
                    HStack(spacing: 12) {
                        if appearance == .terminal { Text(">").foregroundStyle(appearance.accent).accessibilityHidden(true) }
                        TextField("ASCII text", text: $text, prompt: Text("ASCII text").foregroundStyle(appearance.secondary))
                            .keyboardType(.asciiCapable).autocorrectionDisabled().textInputAutocapitalization(.never)
                            .submitLabel(.send).onSubmit { send() }
                            .disabled(model.groupIsBlocked(groupID) || showingGroup || showingFaces || selectedMessage != nil)
                            .padding(.horizontal, 12).frame(minHeight: 44)
                            .background(appearance.background, in: RoundedRectangle(cornerRadius: appearance == .terminal ? 2 : 20))
                            .overlay { RoundedRectangle(cornerRadius: appearance == .terminal ? 2 : 20).strokeBorder(appearance.secondary.opacity(0.35)) }
                        Button("Send", action: send).font(appearance.font(.headline))
                            .foregroundStyle(canSend ? appearance.accent : appearance.secondary).frame(minHeight: 44).disabled(!canSend)
                    }
                    ComposerFooter(text: text, facesEnabled: !model.groupIsBlocked(groupID) && !model.busy && !model.needsAuthentication && model.fatalError == nil && !showingGroup && selectedMessage == nil) {
                        model.setPresentationCovered("ascii-faces", covered: true)
                        showingFaces = true
                    }
                }.padding(.horizontal, 16).padding(.vertical, 12).background(appearance.surface)
            } else { ContentUnavailableView("Group unavailable", systemImage: "lock") }
        }
        .font(appearance.font(.body)).foregroundStyle(appearance.primary).background(appearance.background)
        .navigationTitle(Text(verbatim: group?.title ?? "Group")).navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(appearance.background, for: .navigationBar).toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .principal) {
                ConversationHeading(title: group?.title ?? "Group", subtitle: "\(group?.members.count ?? 0) members · Fixed membership")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button("Group details", systemImage: "info.circle") {
                    model.setPresentationCovered("group-details", covered: true); showingGroup = true
                }.disabled(group == nil)
            }
        }
        .onAppear { model.conversationDidAppear(conversationID) }
        .onDisappear { model.conversationDidDisappear(conversationID) }
        .sheet(isPresented: $showingGroup, onDismiss: { model.setPresentationCovered("group-details", covered: false) }) {
            GroupDetailsView(model: model, groupID: groupID)
        }
        .sheet(item: $selectedMessage, onDismiss: { model.setPresentationCovered("message-details", covered: false) }) { selection in
            MessageDetailsView(model: model, selection: selection)
        }
        .sheet(isPresented: $showingFaces, onDismiss: { model.setPresentationCovered("ascii-faces", covered: false) }) {
            ASCIIFacesPicker(draft: $text, enabled: group != nil && !model.groupIsBlocked(groupID) && !model.busy && !model.needsAuthentication && model.fatalError == nil)
        }
        .onChange(of: model.inboxNavigationSequence) { _, _ in showingGroup = false; selectedMessage = nil; showingFaces = false }
    }

    private func send() {
        guard canSend else { return }
        let submitted = text
        Task { if await model.sendGroup(text: submitted, groupID: groupID), text == submitted { text = "" } }
    }
}

private struct ComposerFooter: View {
    let text: String
    let facesEnabled: Bool
    let showFaces: () -> Void
    @Environment(\.appearance) private var appearance

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) { facesButton; Spacer(minLength: 0); byteCount.fixedSize(horizontal: true, vertical: false) }
            VStack(alignment: .leading, spacing: 4) { facesButton; byteCount.fixedSize(horizontal: false, vertical: true) }
        }
    }

    private var facesButton: some View {
        Button(action: showFaces) {
            HStack(spacing: 6) {
                Text(verbatim: ":-)").font(.system(.subheadline, design: .monospaced)).accessibilityHidden(true)
                Text("ASCII faces").font(appearance.font(.subheadline))
            }.fixedSize(horizontal: true, vertical: false).frame(minHeight: 44)
        }
        .foregroundStyle(facesEnabled ? appearance.accent : appearance.secondary)
        .disabled(!facesEnabled)
        .accessibilityLabel("ASCII faces")
        .accessibilityHint("Choose text to add to the end of your draft")
    }

    private var byteCount: some View {
        Text("7-day expiry · \(text.utf8.count)/1024 bytes")
            .font(appearance.font(.caption)).foregroundStyle(appearance.secondary)
    }
}

private struct ASCIIFacesPicker: View {
    @Binding var draft: String
    let enabled: Bool
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    private var columns: [GridItem] {
        dynamicTypeSize.isAccessibilitySize ? [GridItem(.flexible())] : [GridItem(.adaptive(minimum: 140), spacing: 12)]
    }
    private var hasRoom: Bool { ASCIIFace.allCases.contains { (try? $0.appending(to: draft)) != nil } }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Adds ordinary text to the end of your draft. Review it, then tap Send.")
                        .font(appearance.font(.subheadline)).foregroundStyle(appearance.secondary)
                    LazyVGrid(columns: columns, spacing: 12) {
                        ForEach(ASCIIFace.allCases) { face in
                            let available = enabled && (try? face.appending(to: draft)) != nil
                            Button {
                                guard enabled, let updated = try? face.appending(to: draft) else { return }
                                draft = updated
                                dismiss()
                            } label: {
                                VStack(spacing: 6) {
                                    Text(verbatim: face.text).font(.system(.title2, design: .monospaced))
                                    Text(verbatim: face.name).font(appearance.font(.subheadline))
                                }
                                .foregroundStyle(available ? appearance.primary : appearance.secondary)
                                .frame(maxWidth: .infinity, minHeight: 64).padding(10)
                                .background(appearance.surface, in: RoundedRectangle(cornerRadius: appearance == .terminal ? 2 : 14))
                            }
                            .buttonStyle(.plain).disabled(!available)
                            .accessibilityElement(children: .ignore)
                            .accessibilityLabel(Text(verbatim: face.name))
                            .accessibilityValue(Text(verbatim: face.text))
                            .accessibilityHint("Add this face to your draft")
                        }
                    }
                    if !hasRoom {
                        Text("Make room in your draft or remove unsupported characters to add a face. The limit is 1,024 printable ASCII characters.")
                            .font(appearance.font(.footnote)).foregroundStyle(appearance.warning)
                    }
                }.padding(16)
            }
            .background(appearance.background).foregroundStyle(appearance.primary)
            .navigationTitle("ASCII faces").navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(appearance.background, for: .navigationBar).toolbarBackground(.visible, for: .navigationBar)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        .tint(appearance.accent).preferredColorScheme(appearance.colorScheme)
        .presentationDetents([.medium, .large]).presentationDragIndicator(.visible)
    }
}

private struct ConversationHeading: View {
    let title: String
    let subtitle: String
    @Environment(\.appearance) private var appearance
    var body: some View {
        VStack(spacing: 2) {
            Text(verbatim: title).font(appearance.font(.subheadline).weight(.semibold)).lineLimit(1).truncationMode(.middle)
            Text(verbatim: subtitle).font(appearance.font(.caption2)).foregroundStyle(appearance.secondary).lineLimit(1)
        }.accessibilityElement(children: .combine)
    }
}

private enum MessageRecordedTime {
    static func timestamp(_ message: StoredMessage) -> Int64? {
        if let sent = message.authenticatedSentAt { return sent }
        return message.received_at.flatMap { $0 > 0 ? $0 : nil }
    }
    static func sameDay(_ first: StoredMessage, _ second: StoredMessage) -> Bool {
        switch (timestamp(first), timestamp(second)) {
        case let (.some(first), .some(second)):
            Calendar.current.isDate(Date(timeIntervalSince1970: Double(first)), inSameDayAs: Date(timeIntervalSince1970: Double(second)))
        case (.none, .none): true
        default: false
        }
    }
    static func day(_ message: StoredMessage) -> String {
        guard let timestamp = timestamp(message) else { return "Date not recorded" }
        let date = Date(timeIntervalSince1970: Double(timestamp))
        if Calendar.current.isDateInToday(date) { return "Today" }
        if Calendar.current.isDateInYesterday(date) { return "Yesterday" }
        return date.formatted(date: .abbreviated, time: .omitted)
    }
    static func time(_ message: StoredMessage) -> String {
        guard let timestamp = timestamp(message) else { return "Time not recorded" }
        let time = Date(timeIntervalSince1970: Double(timestamp)).formatted(date: .omitted, time: .shortened)
        return message.authenticatedSentAt == nil ? "Received " + time : time
    }
}

private struct MessageTranscript: View {
    @ObservedObject var model: AppModel
    let conversationID: String
    var selfConversation = false
    var group = false
    let select: (MessageSelection) -> Void
    @Environment(\.appearance) private var appearance

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let messages = model.snapshot?.messages(in: conversationID, at: Int64(context.date.timeIntervalSince1970)) ?? []
            ScrollView {
                LazyVStack(spacing: appearance == .terminal ? 0 : 12) {
                    ForEach(Array(messages.enumerated()), id: \.element.id) { index, message in
                        if index == 0 || !MessageRecordedTime.sameDay(messages[index - 1], message) {
                            Text(verbatim: MessageRecordedTime.day(message))
                                .font(appearance.font(.caption).weight(.medium)).foregroundStyle(appearance.secondary)
                                .padding(.horizontal, 12).padding(.vertical, 7)
                                .background(appearance.surface, in: Capsule())
                                .frame(maxWidth: .infinity).padding(.vertical, 8)
                                .accessibilityAddTraits(.isHeader)
                        }
                        Button {
                            model.setPresentationCovered("message-details", covered: true)
                            select(MessageSelection(id: message.id))
                        } label: {
                            MessageRow(message: message, incoming: !selfConversation && message.sender != model.snapshot?.email,
                                       selfConversation: selfConversation,
                                       pending: model.snapshot?.outbox.contains { $0.id == message.id } == true,
                                       groupAuthor: group ? message.sender : nil)
                        }.buttonStyle(.plain).accessibilityHint("Show message details")
                    }
                    if messages.isEmpty {
                        Text("No messages yet").font(appearance.font(.subheadline)).foregroundStyle(appearance.secondary)
                            .frame(maxWidth: .infinity).padding(.vertical, 32)
                    }
                }.padding(.horizontal, 16).padding(.vertical, 12)
            }
            .defaultScrollAnchor(.bottom).scrollDismissesKeyboard(.interactively)
            .refreshable { await model.refresh() }
        }
    }
}

private struct GroupDetailsView: View {
    @ObservedObject var model: AppModel
    let groupID: String
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss
    private var group: MessageGroup? { model.snapshot?.groups.first { $0.id == groupID } }

    var body: some View {
        NavigationStack {
            Form {
                if let group {
                    Section("Group") {
                        DetailValue("Title", value: group.title)
                        DetailValue("Group ID", value: group.id)
                        Text("Membership and fingerprints are fixed. These are the identities pinned when the group was created, not a claim that another member verified anyone for you.")
                            .font(appearance.font(.footnote))
                        if model.groupIsBlocked(groupID) {
                            Text("Blocked by an identity change. Create a new group after independently verifying the new identity.").foregroundStyle(appearance.warning)
                        }
                    }.listRowBackground(appearance.surface)
                    Section("Members") {
                        ForEach(group.members, id: \.email) { member in
                            VStack(alignment: .leading, spacing: 8) {
                                Text(verbatim: member.email)
                                Text(verbatim: member.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }.listRowBackground(appearance.surface)
                } else { Text("This group is unavailable.").listRowBackground(appearance.surface) }
            }
            .font(appearance.font(.body)).foregroundStyle(appearance.primary)
            .scrollContentBackground(.hidden).background(appearance.background)
            .navigationTitle("Group details").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}

private struct MessageDetailsView: View {
    @ObservedObject var model: AppModel
    let selection: MessageSelection
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            // A clock-driven lookup also hides an expired record at its boundary
            // if a maintenance request is awaiting network I/O. No text is cached.
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Form {
                    if let snapshot = model.snapshot,
                       let message = snapshot.message(id: selection.id, at: Int64(context.date.timeIntervalSince1970)) {
                        Section("Message") {
                            DetailValue("Message ID", value: message.id)
                            if let logical = message.logical_id { DetailValue("Authenticated message ID", value: logical) }
                            DetailValue(message.text == nil ? "Routing sender (unverified)" : "Sender", value: message.sender)
                            if let groupID = message.group_id, let group = snapshot.groups.first(where: { $0.id == groupID }) {
                                DetailValue("Group", value: group.title)
                                DetailValue("Group ID", value: groupID)
                                Text("Recipients are the fixed members listed in Group details.").font(appearance.font(.footnote))
                            } else { DetailValue("Recipient", value: message.recipient) }
                            DetailValue("Text bytes", value: message.text.map { String($0.utf8.count) } ?? "Unavailable: rejected message")
                        }.listRowBackground(appearance.surface)
                        Section("Times") {
                            DetailValue("Sent (authenticated deadline)", value: formatted(message.authenticatedSentAt))
                            DetailValue("Received on this device", value: formatted(message.received_at))
                            DetailValue(message.text == nil ? "Local record expires" : "Expires", value: formatted(message.expires_at))
                            Text("Sent time comes from the authenticated 7-day deadline. Receipt time is this device's clock. Older records may not include either.")
                                .font(appearance.font(.footnote))
                        }.listRowBackground(appearance.surface)
                        Section("Local status") {
                            DetailValue("Status", value: message.text == nil ? "Security rejection" : message.deliveryDescription)
                            if message.text != nil, let accepted = message.accepted_count, let total = message.recipient_count {
                                DetailValue("Relay accepted", value: "\(accepted) of \(total) recipients")
                            }
                            Text("Relay acceptance does not prove receipt or reading. ISYEET has no delivery or read receipts.")
                                .font(appearance.font(.footnote))
                        }.listRowBackground(appearance.surface)
                        Section("Sender identity at message time") {
                            Text(verbatim: message.historicalFingerprint ?? "Not recorded or not authenticated.")
                                .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        }.listRowBackground(appearance.surface)
                    } else {
                        Text("This message has expired, been removed, or is unavailable. No saved copy is kept in this sheet.")
                            .listRowBackground(appearance.surface)
                    }
                }
                .font(appearance.font(.body)).foregroundStyle(appearance.primary)
                .scrollContentBackground(.hidden).background(appearance.background)
            }
            .navigationTitle("Message details").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }

    private func formatted(_ timestamp: Int64?) -> String {
        guard let timestamp, timestamp > 0 else { return "Not recorded" }
        return Date(timeIntervalSince1970: TimeInterval(timestamp)).formatted(date: .abbreviated, time: .standard)
    }
}

private struct DetailValue: View {
    let title: String
    let value: String
    init(_ title: String, value: String) { self.title = title; self.value = value }
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(verbatim: title).font(.caption)
            Text(verbatim: value).textSelection(.enabled)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct RemoveContactView: View {
    @ObservedObject var model: AppModel
    let request: ContactRemoval
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss
    @State private var confirming = false
    @State private var feedback: String?
    @State private var committed = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(verbatim: request.email).font(appearance.font(.headline))
                    Label("REMOVE OLD TRUST", systemImage: "exclamationmark.triangle.fill")
                        .font(appearance.font(.title2).bold()).foregroundStyle(appearance.warning)
                    Text("If this person's key changed, do not assume the new key belongs to them. After removal, add their address again and independently verify the new fingerprint outside ISYEET. Google sign-in is not proof of a key.")
                    Text("This permanently deletes their direct history and pending sends on this device. Existing affected groups remain blocked; create new groups after verifying everyone again.")
                }.listRowBackground(appearance.surface)
                Section("Saved fingerprint being removed") {
                    Text(verbatim: request.previousFingerprint).font(.system(.caption, design: .monospaced))
                }.listRowBackground(appearance.surface)
                if let feedback { Text(verbatim: feedback).foregroundStyle(appearance.warning).listRowBackground(appearance.surface) }
                if !committed {
                    Button("Remove contact and clear history", role: .destructive) { confirming = true }
                        .disabled(model.busy || model.fatalError != nil).listRowBackground(appearance.surface)
                }
            }.font(appearance.font(.body)).foregroundStyle(appearance.primary)
                .scrollContentBackground(.hidden).background(appearance.background)
                .navigationTitle("Remove contact").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button(committed ? "Done" : "Cancel") { dismiss() }.disabled(model.busy) } }
                .confirmationDialog("Remove this saved contact?", isPresented: $confirming, titleVisibility: .visible) {
                    Button("Remove contact and clear history", role: .destructive) {
                        Task {
                            switch await model.removeContact(request) {
                            case .removed: committed = true; dismiss()
                            case .removedPendingSynchronization:
                                committed = true
                                feedback = "Removed on this device. Relay permissions could not be updated yet. Close this screen and refresh or sign in again to stop new deliveries. Add and independently verify the person again only if you want to restore contact."
                            case .failed(let message): feedback = message
                            }
                        }
                    }
                    Button("Cancel", role: .cancel) {}
                } message: { Text("Your own identity and other contacts remain. This contact's direct history and pending sends are deleted, and existing affected groups stay blocked.") }
        }.interactiveDismissDisabled(model.busy)
    }
}

private struct MessageRow: View {
    @Environment(\.appearance) private var appearance
    let message: StoredMessage
    let incoming: Bool
    let selfConversation: Bool
    let pending: Bool
    var groupAuthor: String? = nil

    // The core creates self history only after authenticating the returned
    // relay ciphertext. Outgoing local echoes never become message rows.
    private var delivery: String {
        if selfConversation { return "Received" }
        if message.status != nil { return message.deliveryDescription }
        return pending ? "Queued" : "Relay accepted"
    }

    var body: some View {
        Group {
            if appearance == .terminal {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .firstTextBaseline) {
                        Text(verbatim: groupAuthor.map { (incoming ? "[in] " : "[out] ") + $0 }
                             ?? (selfConversation ? "[self] <you>" : (incoming ? "[in] <contact>" : "[out] <you>")))
                            .font(appearance.font(.caption)).foregroundStyle(appearance.accent)
                        Spacer(minLength: 8)
                        Text(verbatim: MessageRecordedTime.time(message))
                            .font(appearance.font(.caption2)).foregroundStyle(appearance.secondary)
                    }
                    // Trusted author metadata stays outside the indented body.
                    // Soft-wrapped message text cannot occupy the author gutter.
                    messageBody
                        .padding(.leading, 12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .overlay(alignment: .leading) { Rectangle().fill(appearance.secondary).frame(width: 1) }
                    if !incoming && message.text != nil {
                        Text(verbatim: delivery).font(appearance.font(.caption2)).foregroundStyle(appearance.secondary)
                            .padding(.leading, 12)
                    }
                }
                .padding(.vertical, 14)
                .overlay(alignment: .bottom) { Rectangle().fill(appearance.secondary.opacity(0.3)).frame(height: 1) }
            } else {
                VStack(alignment: incoming ? .leading : .trailing, spacing: 5) {
                    if let groupAuthor {
                        Text(verbatim: groupAuthor).font(appearance.font(.caption)).foregroundStyle(appearance.secondary)
                    }
                    messageBody
                        .foregroundStyle(message.text == nil ? appearance.warning : (incoming ? appearance.primary : appearance.outgoingText))
                        .padding(.horizontal, 16).padding(.vertical, 12)
                        .background(message.text == nil || incoming ? appearance.incomingBackground : appearance.outgoingBackground,
                                    in: RoundedRectangle(cornerRadius: 18))
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(verbatim: MessageRecordedTime.time(message))
                        if !incoming && message.text != nil {
                            Text("·").accessibilityHidden(true)
                            Text(verbatim: delivery)
                        }
                    }
                    .font(appearance.font(.caption2)).foregroundStyle(appearance.secondary)
                }
                .padding(incoming ? .trailing : .leading, 36)
                .frame(maxWidth: .infinity, alignment: incoming ? .leading : .trailing)
            }
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder private var messageBody: some View {
        if let text = message.text {
            // Every appearance uses the same validated, literal message text.
            // No Markdown, ANSI escapes, link detection, or command evaluation.
            Text(verbatim: text).font(appearance.font(.body)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text("Security alert: invalid message rejected.")
                .font(appearance.font(.body)).foregroundStyle(appearance.warning)
        }
    }
}
