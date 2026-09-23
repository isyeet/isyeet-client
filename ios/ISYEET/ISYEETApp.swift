import SwiftUI

@main
struct ISYEETApp: App {
    @UIApplicationDelegateAdaptor(PushNotifications.self) private var notifications
    @StateObject private var model = AppModel()
    @AppStorage("isyeet.appearance") private var appearanceSelection = AppAppearance.messaging.rawValue
    @Environment(\.scenePhase) private var scenePhase

    private var appearance: AppAppearance { AppAppearance(rawValue: appearanceSelection) ?? .messaging }

    var body: some Scene {
        WindowGroup {
            HomeView(model: model, notifications: notifications, appearanceSelection: $appearanceSelection)
                .environment(\.appearance, appearance)
                .font(appearance.font(.body))
                .foregroundStyle(appearance.primary)
                .tint(appearance.accent)
                .preferredColorScheme(appearance.colorScheme)
                .privacySensitive()
                .onChange(of: scenePhase, initial: true) { _, phase in model.setAppActive(phase == .active) }
                .onReceive(NotificationCenter.default.publisher(for: UIApplication.significantTimeChangeNotification)) { _ in
                    model.maintainLocalMessages()
                }
                .onChange(of: model.alert) { _, _ in model.updateReadVisibility() }
                .overlay {
                    if scenePhase != .active {
                        appearance.background.ignoresSafeArea()
                            .overlay(Text("ISYEET").font(appearance.font(.title)).foregroundStyle(appearance.accent))
                    }
                }
                .task {
                    notifications.attach(model)
                    await model.start()
                }
                .onChange(of: model.unreadCount) { previous, count in
                    // A cached conversation becoming read must not clear a
                    // newer APNs hint when the inbox cannot be fetched.
                    if count > previous {
                        Task { await notifications.updateBadge(count) }
                    }
                }
                .onChange(of: model.accountLifecycleSequence) { _, _ in
                    notifications.accountDidChange()
                }
                .onChange(of: model.synchronizationSequence) { _, _ in
                    Task {
                        await notifications.updateBadge(model.unreadCount)
                        await notifications.synchronizeRegistration()
                    }
                }
                .onChange(of: model.retentionSequence, initial: true) { _, _ in
                    Task { await notifications.updateBadge(model.unreadCount, preservingRemoteHints: true) }
                }
                .task(id: scenePhase) {
                    guard scenePhase == .active else { return }
                    notifications.attach(model)
                    await notifications.refreshAuthorization()
                    await model.refresh(quiet: true)
                    while !Task.isCancelled {
                        do { try await Task.sleep(for: .seconds(5)) }
                        catch { return }
                        guard !Task.isCancelled else { return }
                        await model.refresh(quiet: true)
                    }
                }
                .alert("ISYEET", isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })) {
                    Button("OK") { model.alert = nil }
                } message: { Text(verbatim: model.alert ?? "") }
        }
    }
}

struct NewMessageNotice: View {
    @ObservedObject var model: AppModel
    @Environment(\.appearance) private var appearance

    var body: some View {
        if model.showsNewMessageIndicator {
            HStack(spacing: 12) {
                Button { model.showInbox() } label: {
                    Label("New message", systemImage: "envelope.badge")
                }
                .font(appearance.font(.subheadline))
                Spacer(minLength: 8)
                Button("Dismiss", systemImage: "xmark") { model.dismissNewMessageIndicator() }
                    .labelStyle(.iconOnly)
                    .accessibilityLabel("Dismiss new message notice")
            }
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 16).padding(.vertical, 12)
            .foregroundStyle(appearance.accent)
            .background(appearance.surface)
        }
    }
}

private enum HomeTab: String, Hashable {
    case messages = "Messages", contacts = "Contacts", settings = "Settings"
}

private enum HomeRoute: Hashable {
    case conversation(String), contact(String)
}

private struct HomeView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var notifications: PushNotifications
    @Binding var appearanceSelection: String
    @Environment(\.appearance) private var appearance
    @State private var tab = HomeTab.messages
    @State private var navigationPath: [HomeRoute] = []
    @State private var composing = false
    @State private var composeNext: HomeRoute?
    @State private var composeStartsGroup = false
    @State private var composeManagesContacts = false
    @State private var addingContact = false
    @State private var addingGroup = false
    @State private var choosingAppearance = false
    @State private var confirmingReenrollment = false
    @State private var confirmingLocalDiscard = false

    var body: some View {
        NavigationStack(path: $navigationPath) {
            Group {
                if let error = model.fatalError {
                    ContentUnavailableView {
                        Label("ISYEET is unavailable", systemImage: "lock")
                    } description: { Text(verbatim: error) } actions: {
                        Button("Retry") { model.retryLoad() }
                    }
                } else if let operation = model.pendingAccountOperation {
                    VStack(alignment: .leading, spacing: 18) {
                        Label("Finish saved account operation", systemImage: "lock.shield").font(appearance.font(.title2).bold())
                        if let email = model.pendingAccountEmail { Text(verbatim: email) }
                        Text(operation == .delete ? "Account deletion is pending. Messages are paused. Retry this same operation; local keys are erased only after the server confirms deletion." : "Device re-enrollment is pending. The prepared keys are saved securely. Retry this same operation; ISYEET will never generate a second replacement just because a reply was lost.")
                        Button("Finish with Google") { Task { await model.resumeAccountOperation() } }.disabled(model.busy)
                        if model.canCancelAccountOperation {
                            Text("The request expired without changing the original registration. Cancel it to return safely; starting again requires new confirmation.")
                            Button("Cancel expired request") { model.cancelExpiredAccountOperation() }.disabled(model.busy)
                        }
                        if model.canDiscardAccountOperation {
                            Text("This saved request can no longer change the current registration. You can explicitly erase this device's local account data and start again.")
                            Button("Clear local account data", role: .destructive) { confirmingLocalDiscard = true }.disabled(model.busy)
                        }
                        if model.busy { ProgressView() }
                        LegalLinks()
                    }.padding(24)
                } else if let email = model.replacedDeviceEmail {
                    VStack(alignment: .leading, spacing: 18) {
                        Label("DEVICE REGISTRATION MISSING OR CHANGED", systemImage: "exclamationmark.triangle.fill")
                            .font(appearance.font(.title2).bold()).foregroundStyle(appearance.warning)
                        Text(verbatim: email)
                        Text("Messaging has stopped because the server registration does not match this device's saved key. Existing history cannot transfer to a new identity. Clear this device only if you intend to sign in or explicitly re-enroll again; contacts must verify any new keys outside ISYEET.")
                        Button("Clear this device's old account data", role: .destructive) { confirmingLocalDiscard = true }.disabled(model.busy)
                        LegalLinks()
                    }.padding(24)
                } else if model.snapshot != nil {
                    VStack(spacing: 0) {
                        NewMessageNotice(model: model)
                        if model.needsAuthentication {
                            Button { Task { await model.signIn() } } label: {
                                Label("Sign in again to send and receive", systemImage: "person.crop.circle.badge.exclamationmark")
                                    .font(appearance.font(.footnote)).frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(.horizontal, 16).padding(.vertical, 10)
                            }.background(appearance.surface).disabled(model.busy)
                        }
                        TabView(selection: $tab) {
                            InboxView(model: model, compose: { composing = true }, reviewContacts: { tab = .contacts })
                                .navigationTitle("Messages")
                                .navigationBarTitleDisplayMode(.inline)
                                .tabItem { Label("Messages", systemImage: "bubble.left.and.bubble.right") }
                                .badge(model.unreadCount).tag(HomeTab.messages)
                            ContactListView(model: model, addContact: { addingContact = true })
                                .navigationTitle("Contacts")
                                .navigationBarTitleDisplayMode(.inline)
                                .tabItem { Label("Contacts", systemImage: "person.crop.circle") }.tag(HomeTab.contacts)
                            SettingsView(model: model, notifications: notifications, appearanceSelection: $appearanceSelection,
                                         chooseAppearance: { choosingAppearance = true })
                                .navigationTitle("Settings")
                                .navigationBarTitleDisplayMode(.inline)
                                .tabItem { Label("Settings", systemImage: "gearshape") }.tag(HomeTab.settings)
                        }
                        .toolbarBackground(appearance.surface, for: .tabBar)
                        .toolbarBackground(.visible, for: .tabBar)
                    }
                } else {
                    VStack(spacing: 24) {
                        Text(appearance == .terminal ? "[isyeet]" : "ISYEET")
                            .font(appearance.font(.largeTitle).bold()).foregroundStyle(appearance.accent)
                        Text("I Send You E2E Text").font(appearance.font(.title2))
                        Text(verbatim: model.environmentTitle).font(appearance.font(.subheadline).bold())
                        if model.isProduction {
                            Text("Production uses separate keys and contacts. Sign in to enroll here; staging data stays on this device.")
                                .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                        }
                        Text("Private text. Google sign-in. Nothing else.").foregroundStyle(appearance.secondary)
                        Button("Continue with Google") { Task { await model.signIn() } }
                            .buttonStyle(.borderedProminent).disabled(model.busy)
                            .foregroundStyle(appearance == .terminal ? appearance.background : .white)
                        if let email = model.reenrollmentEmail {
                            Text(verbatim: email).font(appearance.font(.footnote))
                            Button("Re-enroll this device", role: .destructive) { confirmingReenrollment = true }.disabled(model.busy)
                        }
                        LegalLinks()
                        Text("Only printable ASCII. No images, attachments, or formatted messages.")
                            .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary).multilineTextAlignment(.center)
                    }.padding(28)
                }
            }
            .confirmationDialog("Erase this device's saved account data?", isPresented: $confirmingLocalDiscard, titleVisibility: .visible) {
                Button("Erase local keys and history", role: .destructive) {
                    if model.pendingAccountOperation != nil { model.discardPendingLocalAccount() }
                    else { model.discardReplacedDevice() }
                }
                Button("Cancel", role: .cancel) {}
            } message: { Text("This permanently erases this device's keys, contacts and history. It does not change the current server registration. You must explicitly sign in or re-enroll afterward.") }
            .confirmationDialog("Replace the account's device identity?", isPresented: $confirmingReenrollment, titleVisibility: .visible) {
                Button("Re-enroll and invalidate old device", role: .destructive) { Task { await model.beginReenrollment() } }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This creates new encryption keys. Old messages cannot be recovered and previously issued sessions are revoked. Every contact must remove your old entry, add you again, and independently verify the new fingerprint. Existing affected groups stay blocked. Continue only if you intend to replace the lost device.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(appearance.background)
            .navigationTitle(model.snapshot == nil ? "ISYEET" : tab.rawValue)
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(appearance.background, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                if navigationPath.isEmpty {
                    ToolbarItem(placement: .principal) {
                        Text(verbatim: model.snapshot == nil ? "ISYEET" : (appearance == .terminal ? "[isyeet / \(tab.rawValue.lowercased())]" : tab.rawValue))
                            .font(appearance.font(.headline)).foregroundStyle(appearance.accent)
                    }
                }
                if model.snapshot != nil && navigationPath.isEmpty {
                    if tab == .messages {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("New message", systemImage: "square.and.pencil") { composing = true }
                                .accessibilityIdentifier("newMessageButton")
                        }
                    } else if tab == .contacts {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button("Add contact", systemImage: "person.badge.plus") { addingContact = true }
                                .disabled(model.busy || model.needsAuthentication)
                        }
                    }
                } else if model.snapshot == nil {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Appearance", systemImage: "paintpalette") { choosingAppearance = true }
                    }
                }
                if model.busy { ToolbarItem(placement: .topBarLeading) { ProgressView().accessibilityLabel("Synchronizing") } }
            }
            .navigationDestination(for: HomeRoute.self) { route in
                switch route {
                case .conversation(let id):
                    if id.hasPrefix("group:") { GroupConversationView(model: model, groupID: String(id.dropFirst(6))) }
                    else { ConversationView(model: model, email: id) }
                case .contact(let email):
                    ContactDetailsView(model: model, email: email) {
                        navigationPath.append(.conversation(email))
                    }
                }
            }
            .onChange(of: model.inboxNavigationSequence) { _, _ in
                navigationPath.removeAll()
                tab = .messages
                composeNext = nil; composeStartsGroup = false; composeManagesContacts = false
                composing = false; addingContact = false; addingGroup = false; choosingAppearance = false
            }
            .sheet(isPresented: $composing, onDismiss: {
                if let route = composeNext { navigationPath.append(route); composeNext = nil }
                if composeManagesContacts { tab = .contacts; composeManagesContacts = false }
                if composeStartsGroup { addingGroup = true; composeStartsGroup = false }
            }) {
                ComposeView(model: model) { id in
                    composeNext = .conversation(id); composing = false
                } newGroup: {
                    composeStartsGroup = true; composing = false
                } manageContacts: {
                    composeManagesContacts = true; composing = false
                }
            }
            .sheet(isPresented: $addingContact) { AddContactView(model: model) }
            .sheet(isPresented: $addingGroup) {
                NewGroupView(model: model) { id in navigationPath.append(.conversation("group:" + id)) }
            }
            .sheet(isPresented: $choosingAppearance) { AppearanceView(selection: $appearanceSelection) }
            .onChange(of: composing, initial: true) { _, value in model.setPresentationCovered("compose", covered: value) }
            .onChange(of: addingContact, initial: true) { _, value in model.setPresentationCovered("add-contact", covered: value) }
            .onChange(of: addingGroup, initial: true) { _, value in model.setPresentationCovered("new-group", covered: value) }
            .onChange(of: choosingAppearance, initial: true) { _, value in model.setPresentationCovered("appearance", covered: value) }
        }
    }
}

private struct InboxView: View {
    @ObservedObject var model: AppModel
    let compose: () -> Void
    let reviewContacts: () -> Void
    @Environment(\.appearance) private var appearance
    @State private var unreadOnly = false

    private var needsAttention: Bool {
        !model.pendingUnverified.isEmpty || !model.pendingIdentityChanges.isEmpty
            || model.snapshot?.pending_group_senders.isEmpty == false
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 60)) { context in
            let conversations = model.snapshot?.conversations(unreadCounts: model.unreadCounts, at: Int64(context.date.timeIntervalSince1970)) ?? []
            let visible = conversations.filter { !unreadOnly || $0.unreadCount > 0 }
            List {
                Section {
                    Picker("Conversations", selection: $unreadOnly) {
                        Text("All").tag(false)
                        Text("Unread").tag(true)
                    }.pickerStyle(.segmented).listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
                        .listRowBackground(appearance.background).listRowSeparator(.hidden)
                    if needsAttention {
                        Button(action: reviewContacts) {
                            Label("Messages need contact verification", systemImage: "exclamationmark.shield")
                                .font(appearance.font(.subheadline)).foregroundStyle(appearance.warning)
                        }.listRowBackground(appearance.surface)
                    }
                    if visible.isEmpty {
                        ContentUnavailableView {
                            Label(unreadOnly ? "All caught up" : "No conversations yet", systemImage: unreadOnly ? "checkmark.bubble" : "bubble.left.and.bubble.right")
                        } description: {
                            Text(unreadOnly ? "New messages will appear here." : "Start a private conversation or send yourself a test message.")
                        } actions: {
                            if !unreadOnly { Button("New message", action: compose).buttonStyle(.bordered) }
                        }
                        .listRowBackground(appearance.background).listRowSeparator(.hidden)
                    }
                    ForEach(visible) { conversation in
                        NavigationLink(value: HomeRoute.conversation(conversation.id)) {
                            ConversationSummaryRow(conversation: conversation, accountEmail: model.snapshot?.email ?? "", now: context.date,
                                                   identityChanged: model.pendingIdentityChanges.contains(conversation.id))
                        }.listRowBackground(appearance.surface)
                    }
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("End-to-end encrypted · 7-day expiry", systemImage: "lock")
                        if model.trafficMode == .cover { Text("Cover traffic selected · Foreground only") }
                    }.font(appearance.font(.caption)).foregroundStyle(appearance.secondary).padding(.top, 10)
                }
            }
            .listStyle(.insetGrouped).scrollContentBackground(.hidden)
            .background(appearance.background).refreshable { await model.refresh() }
        }
    }
}

private struct ConversationSummaryRow: View {
    let conversation: ConversationSummary
    let accountEmail: String
    let now: Date
    let identityChanged: Bool
    @Environment(\.appearance) private var appearance
    @ScaledMetric(relativeTo: .body) private var avatarSize = 44

    private var symbol: String {
        switch conversation.kind {
        case .direct: "person.fill"
        case .selfMessage: "arrow.uturn.backward"
        case .group: "person.2.fill"
        }
    }
    private var dateLabel: String? {
        guard let timestamp = conversation.activityAt else { return nil }
        let date = Date(timeIntervalSince1970: Double(timestamp))
        let calendar = Calendar.current
        if calendar.isDate(date, inSameDayAs: now) { return date.formatted(date: .omitted, time: .shortened) }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now), calendar.isDate(date, inSameDayAs: yesterday) { return "Yesterday" }
        return date.formatted(.dateTime.month(.abbreviated).day())
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol).font(appearance.font(.body))
                .foregroundStyle(appearance.accent).frame(width: avatarSize, height: avatarSize)
                .background(appearance.accent.opacity(0.10), in: RoundedRectangle(cornerRadius: appearance == .terminal ? 3 : avatarSize / 2))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(verbatim: conversation.title).font(appearance.font(.subheadline).weight(.semibold)).lineLimit(1)
                        .foregroundStyle(appearance.primary).layoutPriority(1)
                    Spacer(minLength: 0)
                    if let dateLabel {
                        Text(verbatim: dateLabel).font(appearance.font(.caption2)).foregroundStyle(appearance.secondary)
                            .lineLimit(1).fixedSize(horizontal: true, vertical: false)
                    }
                }
                if let sender = conversation.previewSender {
                    Label {
                        Text(verbatim: sender == accountEmail ? "You" : (conversation.kind == .group ? sender : "Contact"))
                            .lineLimit(1)
                    } icon: { Image(systemName: sender == accountEmail ? "arrow.up.right" : "arrow.down.left") }
                    .font(appearance.font(.caption2).weight(.medium)).foregroundStyle(appearance.secondary)
                    .accessibilityLabel(sender == accountEmail ? "Sent by you" : "Received from " + sender)
                }
                HStack(alignment: .top, spacing: 8) {
                    Text(verbatim: conversation.preview).font(appearance.font(.subheadline)).foregroundStyle(appearance.secondary)
                        .lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                    if conversation.unreadCount > 0 {
                        Text("\(conversation.unreadCount)").font(appearance.font(.caption).weight(.semibold))
                            .padding(.horizontal, 7).padding(.vertical, 3)
                            .foregroundStyle(appearance == .terminal ? appearance.background : .white)
                            .background(appearance.accent, in: Capsule())
                            .accessibilityLabel("\(conversation.unreadCount) unread messages")
                    }
                }
                if identityChanged || conversation.blocked {
                    Label(identityChanged || conversation.kind == .group ? "Identity changed · Review verification" : "Contact verification needed", systemImage: "exclamationmark.shield")
                        .font(appearance.font(.caption)).foregroundStyle(appearance.warning)
                } else if let queued = conversation.queuedDescription {
                    Text(verbatim: queued).font(appearance.font(.caption)).foregroundStyle(appearance.secondary)
                }
            }
        }.padding(.vertical, 6).accessibilityElement(children: .combine)
    }
}

private struct ContactListView: View {
    @ObservedObject var model: AppModel
    let addContact: () -> Void
    @Environment(\.appearance) private var appearance

    var body: some View {
        List {
            if let snapshot = model.snapshot {
                if !model.pendingUnverified.isEmpty {
                    Section("Pending messages") {
                        ForEach(model.pendingUnverified, id: \.self) { email in
                            if snapshot.contacts.contains(where: { $0.email == email }) {
                                NavigationLink(value: HomeRoute.contact(email)) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(verbatim: email)
                                        Text("Verify to receive queued messages").font(appearance.font(.caption)).foregroundStyle(appearance.warning)
                                    }
                                }
                            } else {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(verbatim: email)
                                    Button("Add and verify contact") { Task { await model.addContact(email) } }
                                        .disabled(model.busy || model.needsAuthentication)
                                }
                            }
                        }
                    }.listRowBackground(appearance.surface)
                }
                if !snapshot.pending_group_senders.isEmpty {
                    Section("Group verification required") {
                        Text("Ask the sender for the full member list, then independently verify each person outside ISYEET. Group text stays hidden until every member is verified.")
                            .font(appearance.font(.footnote))
                        ForEach(snapshot.pending_group_senders, id: \.self) { Text(verbatim: $0) }
                    }.listRowBackground(appearance.surface)
                }
                let contacts = snapshot.contacts.sorted { a, b in
                    let aNeeds = !a.verified || model.pendingIdentityChanges.contains(a.email)
                    let bNeeds = !b.verified || model.pendingIdentityChanges.contains(b.email)
                    return aNeeds != bNeeds ? aNeeds : a.email < b.email
                }
                Section {
                    if contacts.isEmpty {
                        ContentUnavailableView {
                            Label("Your contacts", systemImage: "person.crop.circle")
                        } description: {
                            Text("Add a Gmail or Workspace address, then verify their identity to start messaging.")
                        } actions: { Button("Add contact", action: addContact).disabled(model.busy || model.needsAuthentication) }
                    }
                    ForEach(contacts) { contact in
                        NavigationLink(value: HomeRoute.contact(contact.email)) {
                            let changed = model.pendingIdentityChanges.contains(contact.email)
                            HStack(spacing: 12) {
                                Image(systemName: changed || !contact.verified ? "exclamationmark.shield" : "checkmark.shield")
                                    .foregroundStyle(changed || !contact.verified ? appearance.warning : appearance.accent)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(verbatim: contact.email).font(appearance.font(.subheadline).weight(.medium))
                                    Text(changed ? "KEY CHANGED · Remove and re-add" : (contact.verified ? "Verified" : "Verification needed"))
                                        .font(appearance.font(.caption)).foregroundStyle(changed || !contact.verified ? appearance.warning : appearance.secondary)
                                }
                            }.padding(.vertical, 4)
                        }
                    }
                } header: { Text("Contacts") } footer: {
                    Text("Verification stays on this device. Compare fingerprints through a trusted channel outside ISYEET.")
                }.listRowBackground(appearance.surface)
            }
        }
        .scrollContentBackground(.hidden).background(appearance.background)
        .refreshable { await model.refresh() }
    }
}

private struct ComposeView: View {
    @ObservedObject var model: AppModel
    let open: (String) -> Void
    let newGroup: () -> Void
    let manageContacts: () -> Void
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                if let snapshot = model.snapshot {
                    Section {
                        Button { open(snapshot.email) } label: { Label("Message yourself", systemImage: "arrow.uturn.backward") }
                        Button(action: newGroup) { Label("New group", systemImage: "person.2") }
                            .disabled(model.busy || model.needsAuthentication || snapshot.groups.count >= 32)
                    }.listRowBackground(appearance.surface)
                    Section("Verified contacts") {
                        let contacts = snapshot.contacts.filter { $0.verified && !model.pendingIdentityChanges.contains($0.email) }.sorted { $0.email < $1.email }
                        if contacts.isEmpty { Text("Add and verify a contact to start a conversation.").foregroundStyle(appearance.secondary) }
                        ForEach(contacts) { contact in
                            Button { open(contact.email) } label: { Text(verbatim: contact.email).foregroundStyle(appearance.primary) }
                        }
                        Button("Manage contacts", action: manageContacts)
                    }.listRowBackground(appearance.surface)
                    if !snapshot.groups.isEmpty {
                        Section("Groups") {
                            ForEach(snapshot.groups) { group in
                                Button { open(group.conversationID) } label: { Text(verbatim: group.title).foregroundStyle(appearance.primary) }
                            }
                        }.listRowBackground(appearance.surface)
                    }
                }
            }
            .scrollContentBackground(.hidden).background(appearance.background)
            .font(appearance.font(.body)).foregroundStyle(appearance.primary)
            .navigationTitle("New message").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
}

private struct SettingsView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var notifications: PushNotifications
    @Binding var appearanceSelection: String
    let chooseAppearance: () -> Void
    @State private var deletingAccount = false
    @State private var legalDocument: BundledLegalDocument?
    @Environment(\.appearance) private var appearance

    var body: some View {
        List {
            if let snapshot = model.snapshot {
                Section("Service") {
                    LabeledContent("Environment", value: model.environmentTitle)
                    Text(verbatim: model.serverOrigin).font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                    Text("Keys and contacts belong only to this service. Switching builds does not transfer an identity or message history.")
                        .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                }.listRowBackground(appearance.surface)
                Section("Open source") {
                    Link("Source code", destination: URL(string: "https://github.com/isyeet/isyeet-client")!)
                    Button("License") { showLegalDocument(.license) }
                    Button("Third-party notices") { showLegalDocument(.notices) }
                    Text("AGPL-3.0-only; no warranty. You may modify and redistribute under its terms. Includes Signal's libsignal; corresponding source and build instructions are linked above.")
                        .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                }.listRowBackground(appearance.surface)
                Section("Your account") {
                    Text(verbatim: snapshot.email)
                    Button("Delete account", role: .destructive) {
                        model.setPresentationCovered("account-action", covered: true)
                        deletingAccount = true
                    }.disabled(model.busy)
                    DisclosureGroup("My identity fingerprint") {
                        Text("Share this through a trusted channel outside ISYEET.").font(appearance.font(.footnote))
                        Text(verbatim: snapshot.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }.listRowBackground(appearance.surface)
                Section("Appearance") {
                    Button(action: chooseAppearance) {
                        HStack {
                            Label("Appearance", systemImage: "paintpalette")
                            Spacer()
                            Text(verbatim: appearance.title).foregroundStyle(appearance.secondary)
                        }
                    }.accessibilityIdentifier("appearanceButton")
                }.listRowBackground(appearance.surface)
                Section("Traffic mode") {
                    Picker("Mode", selection: Binding(get: { model.trafficMode }, set: { mode in Task { await model.setTrafficMode(mode) } })) {
                        ForEach(TrafficMode.allCases) { mode in Text(mode.title).tag(mode) }
                    }.disabled(model.busy || model.needsAuthentication)
                    Text(verbatim: model.trafficStatus).font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                    if model.trafficMode == .cover {
                        Text("Only while ISYEET is open and active: at most one encrypted packet per random 15–45-second slot, with queued real messages first. No catch-up after backgrounding. Groups use one slot per recipient.")
                            .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                        Text("Remote notifications are quiet. Real messages still have local unread indicators. Timing, recipient choice and foreground activity remain observable; this does not prevent traffic analysis.")
                            .font(appearance.font(.footnote)).foregroundStyle(appearance.secondary)
                    } else {
                        if notifications.authorization == .denied {
                            Button("Allow notifications in Settings") {
                                guard let url = URL(string: UIApplication.openNotificationSettingsURLString) else { return }
                                UIApplication.shared.open(url)
                            }
                        } else if notifications.allowed { Label("Notifications allowed", systemImage: "bell") }
                        else { Button("Enable notifications") { Task { await notifications.enable() } }.disabled(notifications.enabling) }
                        if let issue = notifications.issue {
                            Text(verbatim: issue).font(appearance.font(.footnote)).foregroundStyle(appearance.warning)
                        }
                    }
                    if let issue = model.trafficIssue {
                        Text(verbatim: issue).font(appearance.font(.footnote)).foregroundStyle(appearance.warning)
                        Button("Retry mode synchronization") { Task { await model.refresh() } }.disabled(model.busy)
                    }
                }.listRowBackground(appearance.surface)
                Section {
                    LegalLinks()
                    Text("I Send You E2E Text")
                    Text("Printable ASCII only. Messages disappear 7 days after sending, read or unread.").foregroundStyle(appearance.secondary)
                }.font(appearance.font(.footnote)).listRowBackground(appearance.surface)
            }
        }.scrollContentBackground(.hidden).background(appearance.background)
            .refreshable { await model.refresh() }
            .sheet(isPresented: $deletingAccount, onDismiss: { model.setPresentationCovered("account-action", covered: false) }) {
                DeleteAccountView(model: model)
            }
            .sheet(item: $legalDocument, onDismiss: { model.setPresentationCovered("open-source", covered: false) }) { document in
                BundledLegalView(document: document)
            }
    }

    private func showLegalDocument(_ document: BundledLegalDocument) {
        model.setPresentationCovered("open-source", covered: true)
        legalDocument = document
    }
}

private enum BundledLegalDocument: String, Identifiable {
    case license, notices
    var id: String { rawValue }
    var title: String { self == .license ? "License" : "Third-party notices" }
    var content: String {
        let name = self == .license ? "LICENSE" : "THIRD_PARTY_NOTICES"
        guard let url = Bundle.main.url(forResource: name, withExtension: self == .license ? nil : "md"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return "Bundled document unavailable." }
        return text
    }
}

private struct BundledLegalView: View {
    let document: BundledLegalDocument
    @Environment(\.dismiss) private var dismiss
    @Environment(\.appearance) private var appearance
    var body: some View {
        NavigationStack {
            ScrollView {
                Text(verbatim: document.content).font(appearance.font(.body))
                    .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled).padding(20)
            }.background(appearance.background).foregroundStyle(appearance.primary)
                .navigationTitle(document.title).navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
}

private struct LegalLinks: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Link("Privacy policy", destination: URL(string: "https://www.isyeet.io/privacy/")!)
            Link("Terms of service", destination: URL(string: "https://www.isyeet.io/terms/")!)
            Link("Support", destination: URL(string: "https://www.isyeet.io/support/")!)
        }.font(.footnote)
    }
}

private struct DeleteAccountView: View {
    @ObservedObject var model: AppModel
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss
    @State private var confirming = false
    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Label("Delete your ISYEET account", systemImage: "exclamationmark.triangle.fill")
                        .font(appearance.font(.title2).bold()).foregroundStyle(appearance.warning)
                    if let email = model.snapshot?.email { Text(verbatim: email) }
                    Text("This removes your live server registration and queued messages, then erases this device's encryption keys, contacts and history. Cloudflare recovery history may retain copies for up to 30 days. Copies already held by other people cannot be erased. This cannot be undone.")
                    Text("A fresh Google sign-in is required. If interrupted, ISYEET saves this deletion operation and lets you finish it safely.")
                    Button("Delete account", role: .destructive) { confirming = true }.disabled(model.busy)
                }.listRowBackground(appearance.surface)
                Section { LegalLinks() }.listRowBackground(appearance.surface)
            }.font(appearance.font(.body)).foregroundStyle(appearance.primary)
                .scrollContentBackground(.hidden).background(appearance.background)
                .navigationTitle("Delete account").navigationBarTitleDisplayMode(.inline)
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(model.busy) } }
                .confirmationDialog("Permanently delete this account?", isPresented: $confirming, titleVisibility: .visible) {
                    Button("Continue to Google and delete", role: .destructive) { Task { await model.beginAccountDeletion() } }
                    Button("Cancel", role: .cancel) {}
                } message: { Text("After server confirmation, this device's keys and history are erased. There is no recovery.") }
        }.interactiveDismissDisabled(model.busy)
    }
}

private struct AddContactView: View {
    @ObservedObject var model: AppModel
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss
    @State private var email = ""

    var body: some View {
        NavigationStack {
            Form {
                TextField("Gmail or Workspace address", text: $email,
                          prompt: Text("Gmail or Workspace address").foregroundStyle(appearance.secondary))
                    .keyboardType(.emailAddress).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .listRowBackground(appearance.surface)
                Text("After adding the contact, verify their identity fingerprint through a trusted channel before exchanging text.")
                    .font(appearance.font(.footnote))
                    .listRowBackground(appearance.surface)
                Button("Add contact") {
                    Task {
                        await model.addContact(email)
                        if let canonical = try? MessageSafety.canonicalEmail(email),
                           model.snapshot?.contacts.contains(where: { $0.email == canonical }) == true { dismiss() }
                    }
                }.disabled(model.busy || email.isEmpty)
                    .listRowBackground(appearance.surface)
            }
            .font(appearance.font(.body))
            .foregroundStyle(appearance.primary)
            .scrollContentBackground(.hidden)
            .background(appearance.background)
            .navigationTitle("Add contact")
            .toolbarBackground(appearance.background, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
}

private struct NewGroupView: View {
    @ObservedObject var model: AppModel
    let didCreate: (String) -> Void
    @Environment(\.appearance) private var appearance
    @Environment(\.dismiss) private var dismiss
    @State private var title = ""
    @State private var members = Set<String>()

    private var eligible: [Contact] {
        model.snapshot?.contacts.filter { $0.verified && !model.pendingIdentityChanges.contains($0.email) } ?? []
    }
    private var valid: Bool { (try? MessageGroup.validateTitle(title)) != nil && (1...7).contains(members.count) }

    var body: some View {
        NavigationStack {
            Form {
                Section("Group title") {
                    TextField("1–48 ASCII characters", text: $title,
                              prompt: Text("1–48 ASCII characters").foregroundStyle(appearance.secondary))
                        .keyboardType(.asciiCapable).autocorrectionDisabled().textInputAutocapitalization(.never)
                    Text("The title and member list are fixed. Create a new group to change either.")
                        .font(appearance.font(.footnote))
                }.listRowBackground(appearance.surface)
                Section("Choose 1–7 contacts") {
                    if eligible.isEmpty { Text("Add and independently verify contacts first.") }
                    ForEach(eligible) { contact in
                        Toggle(isOn: Binding(get: { members.contains(contact.email) }, set: { selected in
                            if selected { members.insert(contact.email) } else { members.remove(contact.email) }
                        })) { Text(verbatim: contact.email) }
                        .disabled(!members.contains(contact.email) && members.count >= 7)
                    }
                }.listRowBackground(appearance.surface)
                Section {
                    Text("Every member must independently verify every other member outside ISYEET. Creating a group does not verify anyone for another person. Everyone must also permit messages from each other.")
                    Text("Members see the title, full roster and its pinned fingerprints. A re-enrolled member blocks this group; verify their new identity and create a new group.")
                    Button("Create group") {
                        Task {
                            if let id = await model.createGroup(title: title, members: Array(members)) {
                                dismiss(); didCreate(id)
                            }
                        }
                    }.disabled(!valid || model.busy || model.needsAuthentication || model.fatalError != nil)
                }.listRowBackground(appearance.surface)
            }
            .font(appearance.font(.body)).foregroundStyle(appearance.primary)
            .scrollContentBackground(.hidden).background(appearance.background)
            .navigationTitle("New group").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(model.busy) } }
            .interactiveDismissDisabled(model.busy)
        }
    }
}
