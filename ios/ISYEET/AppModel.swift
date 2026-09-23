import Combine
import Foundation
import Security

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var canCancelAccountOperation = false
    @Published private(set) var canDiscardAccountOperation = false
    @Published private(set) var replacedDeviceEmail: String?
    @Published private(set) var pendingAccountOperation: AccountOperationKind?
    @Published private(set) var pendingAccountEmail: String?
    @Published private(set) var reenrollmentEmail: String?
    @Published private(set) var accountLifecycleSequence: UInt64 = 0
    private var operationIntent: AccountOperation?
    @Published private(set) var snapshot: Snapshot?
    @Published private(set) var busy = false
    @Published private(set) var checkingInbox = false
    @Published private(set) var needsAuthentication = true
    @Published private(set) var pendingUnverified: [String] = []
    @Published private(set) var pendingIdentityChanges: [String] = []
    @Published var alert: String?
    @Published private(set) var fatalError: String?
    @Published private(set) var unreadCounts: [String: Int] = [:]
    @Published private(set) var unreadArrivalSequence: UInt64 = 0
    @Published private(set) var synchronizationSequence: UInt64 = 0
    @Published private(set) var retentionSequence: UInt64 = 0
    @Published private(set) var inboxNavigationSequence: UInt64 = 0
    @Published private(set) var showsNewMessageIndicator = false

    @Published private(set) var notificationsResumeAt: Int64?
    @Published private(set) var trafficIssue: String?
    @Published private(set) var coverServerConfirmed = false

    var trafficMode: TrafficMode { snapshot?.traffic.enabled == true ? .cover : .notifications }
    var trafficStatus: String {
        guard trafficMode == .cover else {
            if let deadline = notificationsResumeAt, deadline > Int64(Date().timeIntervalSince1970) {
                return "Notifications resume at " + Date(timeIntervalSince1970: Double(deadline)).formatted(date: .omitted, time: .standard) + ". Previously shared cover consent is expiring."
            }
            return "Alerts say only New message. No sender or message preview."
        }
        guard coverServerConfirmed else { return "Cover traffic paused until the server confirms notifications are quiet." }
        guard !needsAuthentication else { return "Cover traffic paused. Sign in again with the same account." }
        guard let traffic = snapshot?.traffic else { return "Cover traffic paused." }
        if traffic.remaining_budget == 0 { return "Weekly cover budget reached. Queued real messages still use scheduled slots." }
        if !traffic.cover_outbox_ids.isEmpty {
            return "A cover packet is queued for a future slot. Real messages take priority. \(traffic.remaining_budget) cover packets left this week."
        }
        if traffic.eligible_contacts.isEmpty && snapshot?.outbox.isEmpty == false {
            return "Queued real messages use the next sending slots. Cover packets wait for fresh mutual consent and available capacity."
        }
        if traffic.eligible_contacts.isEmpty {
            return "No eligible contact. Both people must choose Cover traffic and exchange real messages to establish fresh consent. Offline or full contacts pause cover packets."
        }
        return "\(traffic.remaining_budget) cover packets left this week. \(traffic.outstanding) awaiting a peer receipt or expiry."
    }

    var unreadCount: Int { unreadCounts.values.reduce(0, +) }

    var environmentTitle: String { configuration?.environment.title ?? "Unavailable" }
    var serverOrigin: String { configuration?.server.absoluteString ?? "" }
    var isProduction: Bool { configuration?.environment == .production }
    private var vault: Vault {
        get throws {
            guard let configuration else { throw SafetyError.configuration }
            return try Vault(server: configuration.server)
        }
    }
    private let core = CryptoBridge()
    private let oauth = GoogleOAuth()
    private var account: StoredAccount?
    private var lockedAccount: StoredAccount?
    private var lockedExpiry: Int64?
    private var configuration: Configuration?
    private var started = false
    private var readContext = MessageReadContext()
    private var coveringPresentations = Set<String>()
    private var expiryTask: Task<Void, Never>?
    private var coverTimer: Task<Void, Never>?
    private var coverTransmission: Task<Void, Never>?
    private var coverCadence = CoverCadence()
    private let coverClock = ContinuousClock()
    private var coverForegroundRevision: UInt64 = 0
    private var lastScheduledEnvelopeID: String?
    private var observedIdentityChanges: [String: String] = [:]
    private var updatingContactVerification: Bool { coveringPresentations.contains("contact-remove") || coveringPresentations.contains("account-action") }

    private var currentReadContext: MessageReadContext {
        var result = readContext
        result.covered = !coveringPresentations.isEmpty || alert != nil || fatalError != nil
        return result
    }

    func setAppActive(_ active: Bool) {
        if readContext.appActive != active {
            coverForegroundRevision &+= 1
            coverServerConfirmed = false
        }
        readContext.appActive = active
        if active { maintainLocalMessages() }
        else { expiryTask?.cancel(); expiryTask = nil; stopCoverSchedule() }
        updateReadVisibility()
        scheduleCoverTraffic()
    }

    func conversationDidAppear(_ email: String) {
        readContext.visibleConversation = email
        maintainLocalMessages()
        updateReadVisibility()
    }

    func conversationDidDisappear(_ email: String) {
        if readContext.visibleConversation == email { readContext.visibleConversation = nil }
    }

    func setPresentationCovered(_ identifier: String, covered: Bool) {
        if covered { coveringPresentations.insert(identifier) }
        else { coveringPresentations.remove(identifier) }
        updateReadVisibility()
    }

    func dismissNewMessageIndicator() { showsNewMessageIndicator = false }

    func showInbox() {
        readContext.visibleConversation = nil
        inboxNavigationSequence &+= 1
    }

    func updateReadVisibility() {
        guard currentReadContext.readableConversation != nil, var proposed = account, let snapshot else { return }
        let updated = UnreadMessages.updatedIDs(proposed.unreadMessageIDs, snapshot: snapshot, reading: currentReadContext)
        guard updated != proposed.unreadMessageIDs else { return }
        proposed.unreadMessageIDs = updated
        do { try persist(proposed) }
        catch { report(error) }
    }

    init() {
        loadAccount()
    }

    func retryLoad() {
        guard !busy else { return }
        loadAccount()
    }

    private func loadAccount() {
        do {
            let configuration = try Configuration()
            self.configuration = configuration
            lockedAccount = nil
            lockedExpiry = nil
            if let operation = try vault.loadOperation() {
                guard operation.backend == configuration.server.absoluteString else { throw SafetyError.accountMismatch }
                try pauseForAccountOperation(operation)
                fatalError = nil
                scheduleExpiry()
                return
            }
            operationIntent = nil
            pendingAccountOperation = nil
            pendingAccountEmail = nil
            if let stored = try vault.load() {
                guard stored.backend == configuration.server.absoluteString else { throw SafetyError.accountMismatch }
                if stored.identityReplaced {
                    account = nil
                    lockedAccount = stored
                    snapshot = nil
                    needsAuthentication = true
                    replacedDeviceEmail = stored.email
                    stopCoverSchedule()
                    fatalError = nil
                    try maintainLockedAccount()
                    scheduleExpiry()
                    return
                }
                // Core expiry (including an upgrade) must be saved before any
                // plaintext reaches the published snapshot, even when offline.
                try persist(stored, recovering: true)
                needsAuthentication = stored.expiresAt <= Int64(Date().timeIntervalSince1970)
            }
            fatalError = nil
            scheduleExpiry()
        } catch { hideMessagesAfterMaintenanceFailure(error) }
    }

    // This intentionally ignores network activity and OAuth session validity.
    // A suspended network request must never delay removal from the screen.
    func maintainLocalMessages() {
        guard fatalError == nil else { return }
        do { try maintain() }
        catch { hideMessagesAfterMaintenanceFailure(error) }
    }

    private func maintain() throws {
        do {
            if lockedAccount != nil { try maintainLockedAccount() }
            else if let account { try persist(account) }
        }
        catch { hideMessagesAfterMaintenanceFailure(error); throw error }
    }

    // Locked accounts retain keys for recovery but never publish their plaintext.
    // Their original expiry deadlines still run without authentication/network.
    private func maintainLockedAccount() throws {
        guard var proposed = lockedAccount else { return }
        for email in Set(proposed.contactIdentityChanges) {
            let result = try core.call("block_groups_for_contact", state: proposed.core, fields: ["email": .string(email)])
            guard let state = result.state else { throw SafetyError.persistence }
            proposed.core = state
        }
        while true {
            let result = try core.expire(proposed.core)
            proposed.core = result.state
            proposed.unreadMessageIDs = UnreadMessages.updatedIDs(proposed.unreadMessageIDs, snapshot: result.snapshot,
                reading: MessageReadContext(), now: Int64(Date().timeIntervalSince1970))
            if proposed != lockedAccount {
                try vault.save(proposed)
                // Adopt every successful save before any subsequent slow-write
                // expiry iteration can fail. Never rewrite an older ratchet.
                lockedAccount = proposed
            }
            if let deadline = result.snapshot.nextExpiry, deadline <= Int64(Date().timeIntervalSince1970) {
                let next = try core.expire(proposed.core)
                guard next.state != proposed.core else { throw SafetyError.invalidResponse }
                proposed.core = next.state
                continue
            }
            lockedExpiry = result.snapshot.nextExpiry
            scheduleExpiry()
            return
        }
    }

    private func hideMessagesAfterMaintenanceFailure(_ error: Error) {
        expiryTask?.cancel()
        expiryTask = nil
        stopCoverSchedule()
        coverServerConfirmed = false
        snapshot = nil
        unreadCounts = [:]
        showsNewMessageIndicator = false
        fatalError = safeDescription(error)
    }

    private func scheduleExpiry() {
        expiryTask?.cancel()
        expiryTask = nil
        guard readContext.appActive, fatalError == nil, let deadline = snapshot?.nextExpiry ?? lockedExpiry else { return }
        let delay = max(0.05, Double(deadline) - Date().timeIntervalSince1970)
        expiryTask = Task { @MainActor [weak self] in
            do { try await Task.sleep(for: .seconds(delay)) }
            catch { return }
            guard let self, !Task.isCancelled else { return }
            self.expiryTask = nil
            self.maintainLocalMessages()
        }
    }

    // Secure random rejection sampling avoids modulo bias and adds no new library.
    private func randomIndex(upperBound: UInt32) throws -> UInt32 {
        guard upperBound > 0 else { throw SafetyError.invalidResponse }
        let threshold = (0 &- upperBound) % upperBound
        while true {
            var value: UInt32 = 0
            guard SecRandomCopyBytes(kSecRandomDefault, MemoryLayout.size(ofValue: value), &value) == errSecSuccess else {
                throw SafetyError.trafficUnavailable
            }
            if value >= threshold { return value % upperBound }
        }
    }

    private func nextCoverDelay() throws -> Duration { .milliseconds(Int64(15_000 + (try randomIndex(upperBound: 30_001)))) }

    private func stopCoverSchedule() {
        coverTimer?.cancel()
        coverTimer = nil
        coverCadence.stop()
        // A request already in flight may have reached the relay. Keep its
        // exact durable envelope until acceptance is saved or a later retry.
    }

    private func scheduleCoverTraffic() {
        guard readContext.appActive, trafficMode == .cover, fatalError == nil, operationIntent == nil, account?.identityReplaced != true else { stopCoverSchedule(); return }
        guard coverTimer == nil else { return } // Send, refresh and retry cannot reset the clock.
        do { coverCadence.arm(now: coverClock.now, delay: try nextCoverDelay()) }
        catch { trafficIssue = safeDescription(error); return }
        coverTimer = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                guard let deadline = self?.coverCadence.deadline else { return }
                do { try await ContinuousClock().sleep(until: deadline) }
                catch { return }
                guard let self, !Task.isCancelled else { return }
                do {
                    guard self.coverCadence.consume(now: self.coverClock.now, nextDelay: try self.nextCoverDelay()) else { continue }
                    // Skip missed/busy slots. Never catch up after a slow request,
                    // foreground pause, or user operation.
                    if self.coverTransmission == nil {
                        self.coverTransmission = Task { @MainActor [weak self] in
                            guard let self else { return }
                            await self.sendCoverSlot()
                            self.coverTransmission = nil
                        }
                    }
                } catch { self.trafficIssue = self.safeDescription(error); self.stopCoverSchedule(); return }
            }
        }
    }

    private func outgoingAllowed(_ envelope: SendRequest) -> Bool {
        if pendingIdentityChanges.contains(envelope.recipient) { return false }
        if let reference = snapshot?.outbox_refs.first(where: { $0.id == envelope.id }), groupIsBlocked(reference.group_id) { return false }
        return true
    }

    // Exactly one envelope per caller-granted slot. The timer grants slots only
    // from its monotonic cadence, independent of plaintext/user actions.
    func sendCoverSlot() async {
        guard readContext.appActive, trafficMode == .cover,
              !busy, !needsAuthentication, fatalError == nil, !updatingContactVerification else { return }
        busy = true
        defer { busy = false }
        do {
            let (current, api) = try authenticated()
            guard current.registered else { return }
            // Every slot checks the same account-only endpoint, regardless of
            // whether real text or a cover will use it. Its bounded monotonic
            // round trip anchors the core's separate cover-consent clock.
            let revision = coverForegroundRevision
            let started = coverClock.now
            guard let policy = try await api.trafficMode(token: current.token, allowLegacy: false), policy.cover,
                  let state = account?.core else { throw SafetyError.trafficUnavailable }
            try apply(quietConfirmation(policy, state: state, started: started, revision: revision))
            coverServerConfirmed = true
            guard let snapshot else { throw SafetyError.persistence }
            let covers = Set(snapshot.traffic.cover_outbox_ids)
            let real = snapshot.outbox.filter { !covers.contains($0.id) && outgoingAllowed($0) }
            // One failed recipient must not monopolize all later slots. This
            // cursor is only scheduling fairness; durable retry IDs stay intact.
            var outgoing: SendRequest?
            if let previous = real.firstIndex(where: { $0.id == lastScheduledEnvelopeID }), !real.isEmpty {
                outgoing = real[(previous + 1) % real.count]
            } else { outgoing = real.first }
            if outgoing == nil { outgoing = snapshot.outbox.first { covers.contains($0.id) && outgoingAllowed($0) } }
            if outgoing == nil {
                let eligible = snapshot.traffic.eligible_contacts.filter { !pendingIdentityChanges.contains($0) }
                guard !eligible.isEmpty, snapshot.traffic.remaining_budget > 0 else { return }
                let recipient = eligible[Int(try randomIndex(upperBound: UInt32(eligible.count)))]
                guard let state = account?.core else { throw SafetyError.persistence }
                try apply(core.call("create_cover", state: state, fields: ["recipient": .string(recipient)]))
                outgoing = self.snapshot?.outbox.first { self.snapshot?.traffic.cover_outbox_ids.contains($0.id) == true }
            }
            guard let outgoing, readContext.appActive, trafficMode == .cover, coverServerConfirmed else { return }
            lastScheduledEnvelopeID = outgoing.id
            try await api.send(outgoing, token: current.token)
            guard let state = account?.core else { throw SafetyError.persistence }
            try apply(core.call("sent", state: state, fields: ["id": .string(outgoing.id)]))
            trafficIssue = nil
        } catch {
            coverServerConfirmed = false
            if case CoreError.coverClockUnavailable = error {
                trafficIssue = CoreError.coverClockUnavailable.errorDescription
                return
            }
            if case CoreError.coverUnavailable = error {
                trafficIssue = CoreError.coverUnavailable.errorDescription
                return
            }
            if error as? SafetyError == .unauthorized { needsAuthentication = true }
            trafficIssue = "Scheduled sending paused or failed. The next eligible slot retries saved ciphertext."
            if error as? SafetyError == .persistence || error is CoreError { report(error) }
        }
    }

    func setTrafficMode(_ mode: TrafficMode) async {
        guard !busy, fatalError == nil, operationIntent == nil, !updatingContactVerification else { return }
        busy = true
        defer { busy = false; scheduleCoverTraffic() }
        do {
            let (current, api) = try authenticated()
            if mode == .cover {
                // The relay must be durably quiet before any encrypted packet
                // can advertise this account's willingness to receive covers.
                let revision = coverForegroundRevision
                let started = coverClock.now
                let response = try await api.setTrafficMode(cover: true, token: current.token)
                guard fatalError == nil, let state = account?.core else { throw SafetyError.persistence }
                let enabled = try core.call("set_traffic_mode", state: state, fields: ["enabled": .bool(true)])
                guard let enabledState = enabled.state else { throw SafetyError.persistence }
                let confirmed = try quietConfirmation(response, state: enabledState, started: started, revision: revision)
                try apply(confirmed, resolvedMessageIDs: enabled.resolved_message_ids ?? [])
                coverServerConfirmed = true
                notificationsResumeAt = response.notifications_resume_at
            } else {
                guard let state = account?.core else { throw SafetyError.persistence }
                try apply(core.call("set_traffic_mode", state: state, fields: ["enabled": .bool(false)]))
                coverServerConfirmed = false
                // Revoking consent and cancelling queued covers is durable
                // before starting the server's seven-minute quiet grace.
                let response = try await api.setTrafficMode(cover: false, token: current.token)
                notificationsResumeAt = response.notifications_resume_at
            }
            trafficIssue = nil
        } catch {
            coverServerConfirmed = false
            trafficIssue = "Traffic mode could not be fully synchronized. Notifications may remain quiet. Refresh to retry."
            report(error)
        }
    }

    private func reconcileTrafficMode(_ api: API, token: String) async throws {
        let enabled = trafficMode == .cover
        let revision = coverForegroundRevision
        let started = coverClock.now
        do {
            guard var response = try await api.trafficMode(token: token, allowLegacy: !enabled) else {
                coverServerConfirmed = false
                notificationsResumeAt = 0
                trafficIssue = nil
                return
            }
            if response.cover != enabled { response = try await api.setTrafficMode(cover: enabled, token: token) }
            guard fatalError == nil else { throw SafetyError.persistence }
            if enabled {
                guard let state = account?.core else { throw SafetyError.persistence }
                try apply(quietConfirmation(response, state: state, started: started, revision: revision))
                coverServerConfirmed = true
            } else { coverServerConfirmed = false }
            notificationsResumeAt = response.notifications_resume_at
            trafficIssue = nil
        } catch {
            coverServerConfirmed = false
            trafficIssue = "Traffic mode could not be confirmed. Refresh to retry; notifications may remain quiet."
            throw error
        }
    }

    private func quietConfirmation(_ policy: TrafficModeResponse, state: JSONValue,
                                   started: ContinuousClock.Instant, revision: UInt64) throws -> CoreResult {
        guard policy.cover, readContext.appActive, revision == coverForegroundRevision,
              fatalError == nil else { throw SafetyError.trafficUnavailable }
        let elapsed = try TrafficClock.elapsedSeconds(from: started, to: coverClock.now)
        return try core.call("confirm_traffic_quiet", state: state,
                             fields: ["server_time": .integer(policy.server_time), "elapsed_seconds": .integer(elapsed)])
    }

    func start() async {
        guard !started else { return }
        started = true
        #if DEBUG && targetEnvironment(simulator)
        guard fatalError == nil, let configuration, let email = configuration.simulatorDevelopmentEmail else { return }
        await run {
            let login = try await API(base: configuration.server).simulatorDevelopmentLogin(email: email)
            try await acceptLogin(login, configuration: configuration)
            try await synchronize()
            if let fingerprint = snapshot?.fingerprint {
                let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                    .appendingPathComponent("simulator-public-fingerprint.txt")
                try Data(fingerprint.utf8).write(to: url, options: .atomic)
            }
        }
        let environment = ProcessInfo.processInfo.environment
        if let email = environment["ISYEET_SIMULATOR_CONTACT_EMAIL"],
           let fingerprint = environment["ISYEET_SIMULATOR_CONTACT_FINGERPRINT"] {
            await addContact(email)
            await verifyContact(email: email, fingerprint: fingerprint)
            if let text = environment["ISYEET_SIMULATOR_SEND_TEXT"] { _ = await send(text: text, recipient: email) }
        }
        #endif
    }

    func signIn() async {
        guard !busy, fatalError == nil, operationIntent == nil, let configuration else { return }
        busy = true
        defer { busy = false }
        do {
            let credential = try await oauth.idToken(configuration: configuration)
            let login = try await API(base: configuration.server).login(idToken: credential.idToken)
            guard login.email == credential.email else { throw SafetyError.accountMismatch }
            do { try await acceptLogin(login, configuration: configuration) }
            catch SafetyError.identityAlreadyRegistered {
                reenrollmentEmail = credential.email
                throw SafetyError.identityAlreadyRegistered
            }
            reenrollmentEmail = nil
            try await synchronize()
        } catch { report(error) }
    }

    private func pauseForAccountOperation(_ operation: AccountOperation) throws {
        operationIntent = operation
        canCancelAccountOperation = false
        canDiscardAccountOperation = false
        pendingAccountOperation = operation.kind
        pendingAccountEmail = operation.email
        lockedAccount = try account ?? lockedAccount ?? vault.load()
        account = nil
        snapshot = nil
        unreadCounts = [:]
        pendingIdentityChanges = []
        pendingUnverified = []
        observedIdentityChanges = [:]
        showsNewMessageIndicator = false
        needsAuthentication = true
        expiryTask?.cancel(); expiryTask = nil
        stopCoverSchedule()
        coverServerConfirmed = false
        showInbox()
        do { try maintainLockedAccount() }
        catch { hideMessagesAfterMaintenanceFailure(error); throw error }
    }

    func beginAccountDeletion() async { await beginAccountOperation(.delete) }
    func beginReenrollment() async { await beginAccountOperation(.reenroll) }

    private func beginAccountOperation(_ kind: AccountOperationKind) async {
        guard !busy, fatalError == nil, operationIntent == nil, let configuration else { return }
        let target = kind == .delete ? account?.email : reenrollmentEmail
        let pinnedIdentity = kind == .delete ? snapshot?.fingerprint : nil
        guard let target, kind != .delete || pinnedIdentity != nil else { return }
        busy = true
        defer { busy = false }
        do {
            let credential = try await oauth.idToken(configuration: configuration)
            guard credential.email == target, fatalError == nil else { throw SafetyError.accountMismatch }
            let api = API(base: configuration.server)
            guard let remote = try await api.accountState(idToken: credential.idToken, email: target) else { throw SafetyError.accountOperationConflict }
            guard fatalError == nil else { throw SafetyError.persistence }
            var preparedCore: JSONValue?
            var preparedKeys: JSONValue?
            var preparedFingerprint: String?
            if kind == .delete {
                guard account?.email == target, snapshot?.fingerprint == pinnedIdentity,
                      (remote.identity_fingerprint == pinnedIdentity || (remote.identity_fingerprint == nil && account?.registered == false)) else { throw SafetyError.accountOperationConflict }
            } else {
                guard account == nil, remote.identity_fingerprint != nil else { throw SafetyError.accountOperationConflict }
                let created = try core.call("init", fields: ["email": .string(target)])
                guard let state = created.state else { throw SafetyError.persistence }
                let upload = try core.call("key_upload", state: state)
                guard let keys = upload.data, let keyState = upload.state else { throw SafetyError.persistence }
                let ready = try core.expire(keyState)
                guard ready.snapshot.email == target else { throw SafetyError.invalidResponse }
                preparedCore = ready.state
                preparedKeys = keys
                preparedFingerprint = ready.snapshot.fingerprint
            }
            let intent = try AccountOperation(kind: kind, backend: configuration.server.absoluteString,
                email: target, operationID: UUID().uuidString.lowercased(), expiresAt: remote.server_time + 900,
                expectedGeneration: remote.generation, expectedFingerprint: remote.identity_fingerprint,
                preparedCore: preparedCore, preparedKeys: preparedKeys, preparedFingerprint: preparedFingerprint).validated()
            // This durable journal is the point of no implicit cancellation.
            // No destructive HTTP request may happen before it succeeds.
            try vault.saveOperation(intent)
            try pauseForAccountOperation(intent)
            try await finishAccountOperation(idToken: credential.idToken)
        } catch { report(error) }
    }

    func resumeAccountOperation() async {
        guard !busy, fatalError == nil, let intent = operationIntent, let configuration else { return }
        busy = true
        defer { busy = false }
        do {
            if intent.discardLocal { try completeLocalDiscard(); return }
            // A durably recorded deletion receipt needs only local cleanup.
            if intent.completed && intent.kind == .delete { try completeAccountDeletion(); return }
            let credential = try await oauth.idToken(configuration: configuration)
            guard credential.email == intent.email else { throw SafetyError.accountMismatch }
            try await finishAccountOperation(idToken: credential.idToken)
        } catch { report(error) }
    }

    private func finishAccountOperation(idToken: String) async throws {
        guard var intent = operationIntent, let configuration, fatalError == nil else { throw SafetyError.persistence }
        let api = API(base: configuration.server)
        if !intent.completed {
            do { try await api.performAccountOperation(intent, idToken: idToken) }
            catch SafetyError.accountOperationConflict {
                if try await reconcileAccountOperation(idToken: idToken) { return }
                throw SafetyError.accountOperationConflict
            }
            guard fatalError == nil, operationIntent == intent else { throw SafetyError.persistence }
            intent.completed = true
            // Persist the server receipt before erasing any original local key.
            try vault.saveOperation(intent)
            operationIntent = intent
        }
        if intent.kind == .delete { try completeAccountDeletion(); return }
        do { try await activateReenrollment(intent, idToken: idToken, api: api) }
        catch SafetyError.accountOperationConflict {
            if try await reconcileAccountOperation(idToken: idToken) { return }
            throw SafetyError.accountOperationConflict
        }
    }

    private func activateReenrollment(_ intent: AccountOperation, idToken: String, api: API) async throws {
        let login = try await api.login(idToken: idToken)
        guard login.email == intent.email else { throw SafetyError.accountMismatch }
        guard let keys = try await api.ownKeys(token: login.token) else { throw SafetyError.accountOperationConflict }
        try intent.validateCurrentKeys(keys)
        guard fatalError == nil, operationIntent == intent, let coreState = intent.preparedCore else { throw SafetyError.persistence }
        let confirmation = try core.call("confirm_initial_upload", state: coreState)
        guard let confirmedState = confirmation.state else { throw SafetyError.persistence }
        let ready = try core.expire(confirmedState)
        guard ready.snapshot.email == intent.email, ready.snapshot.fingerprint == intent.preparedFingerprint else { throw SafetyError.invalidResponse }
        let restored = StoredAccount(version: 1, backend: intent.backend, email: intent.email,
            token: login.token, expiresAt: login.expires_at, core: ready.state, registered: true)
        // Until both writes finish, startup sees the intent and cannot use an
        // old identity or regenerate a second replacement after an uncertain reply.
        try vault.save(restored)
        lockedAccount = restored
        try vault.clearOperation()
        operationIntent = nil
        pendingAccountOperation = nil
        pendingAccountEmail = nil
        reenrollmentEmail = nil
        loadAccount()
        guard fatalError == nil else { throw SafetyError.persistence }
        accountLifecycleSequence &+= 1
        alert = "Re-enrollment completed. Previously issued sessions were revoked. Ask every contact to remove your old contact entry, add you again, and verify your new fingerprint outside ISYEET. Create new affected groups."
    }

    private func reconcileAccountOperation(idToken: String) async throws -> Bool {
        guard var intent = operationIntent, let configuration, fatalError == nil else { throw SafetyError.persistence }
        canCancelAccountOperation = false
        canDiscardAccountOperation = false
        let api = API(base: configuration.server)
        let remote = try await api.accountState(idToken: idToken, email: intent.email)
        guard operationIntent == intent, fatalError == nil else { throw SafetyError.persistence }
        guard let remote else {
            if intent.kind == .delete {
                intent.completed = true
                try vault.saveOperation(intent); operationIntent = intent
                try completeAccountDeletion()
                return true
            }
            // State lookup never creates an account. A missing account cannot
            // satisfy the original generation CAS if that request arrives late.
            canDiscardAccountOperation = true
            throw SafetyError.accountOperationConflict
        }
        if intent.kind == .reenroll, remote.identity_fingerprint == intent.preparedFingerprint {
            canDiscardAccountOperation = remote.server_time >= intent.expiresAt
            intent.completed = true
            try vault.saveOperation(intent); operationIntent = intent
            try await activateReenrollment(intent, idToken: idToken, api: api)
            return true
        }
        if remote.generation == intent.expectedGeneration && remote.identity_fingerprint == intent.expectedFingerprint {
            if remote.server_time >= intent.expiresAt {
                if intent.completed { canDiscardAccountOperation = true }
                else { canCancelAccountOperation = true }
                throw SafetyError.accountOperationConflict
            }
            return false
        }
        // Never silently renew a destructive request against another generation.
        canDiscardAccountOperation = remote.server_time >= intent.expiresAt
        throw SafetyError.accountOperationConflict
    }

    func cancelExpiredAccountOperation() {
        guard !busy, canCancelAccountOperation else { return }
        do {
            try vault.clearOperation()
            operationIntent = nil
            pendingAccountOperation = nil
            pendingAccountEmail = nil
            canCancelAccountOperation = false
            loadAccount()
        } catch { report(error) }
    }

    func discardPendingLocalAccount() {
        guard !busy, canDiscardAccountOperation, var intent = operationIntent else { return }
        do {
            intent.discardLocal = true
            try vault.saveOperation(intent)
            operationIntent = intent
            try completeLocalDiscard()
        } catch { report(error) }
    }

    private func completeLocalDiscard() throws {
        guard let intent = operationIntent, intent.discardLocal else { throw SafetyError.persistence }
        try vault.deleteAccount()
        lockedAccount = nil
        lockedExpiry = nil
        try vault.clearOperation()
        operationIntent = nil
        pendingAccountOperation = nil
        pendingAccountEmail = nil
        canDiscardAccountOperation = false
        reenrollmentEmail = intent.email
        account = nil
        snapshot = nil
        replacedDeviceEmail = nil
        accountLifecycleSequence &+= 1
        alert = "This device's local account data was cleared. The server account was not changed. Sign in or explicitly choose Re-enroll this device to continue."
    }

    func discardReplacedDevice() {
        guard !busy, let account = lockedAccount, account.identityReplaced else { return }
        do {
            // The durable identityReplaced marker makes a crash during local
            // erasure safe; it never permits this old core to resume messaging.
            try vault.deleteAccount()
            lockedAccount = nil
            lockedExpiry = nil
            reenrollmentEmail = account.email
            self.account = nil
            replacedDeviceEmail = nil
            snapshot = nil
            needsAuthentication = true
            accountLifecycleSequence &+= 1
        } catch { report(error) }
    }

    private func completeAccountDeletion() throws {
        guard operationIntent?.kind == .delete, operationIntent?.completed == true else { throw SafetyError.persistence }
        try vault.deleteAccount()
        lockedAccount = nil
        lockedExpiry = nil
        try vault.clearOperation()
        operationIntent = nil
        pendingAccountOperation = nil
        pendingAccountEmail = nil
        reenrollmentEmail = nil
        accountLifecycleSequence &+= 1
        alert = "The requested account deletion is complete, and this device's keys and history were cleared. An account created afterward is not affected. Copies held by other people cannot be erased."
    }

    private func lockChangedRegistration() throws {
        guard fatalError == nil, var blocked = account else { throw SafetyError.persistence }
        blocked.identityReplaced = true
        blocked.token = ""
        blocked.expiresAt = 0
        do { try vault.save(blocked) }
        catch { hideMessagesAfterMaintenanceFailure(error); throw error }
        account = nil
        lockedAccount = blocked
        snapshot = nil
        unreadCounts = [:]
        needsAuthentication = true
        replacedDeviceEmail = blocked.email
        stopCoverSchedule()
        expiryTask?.cancel(); expiryTask = nil
        showInbox()
        do { try maintainLockedAccount() }
        catch { hideMessagesAfterMaintenanceFailure(error); throw error }
    }

    private func acceptLogin(_ login: LoginResponse, configuration: Configuration) async throws {
        var proposed: StoredAccount
        var resolvedMessageIDs: [String] = []
        if let existing = account {
            guard existing.email == login.email else { throw SafetyError.accountMismatch }
            guard !existing.identityReplaced else { throw SafetyError.deviceIdentityReplaced }
            var validatedState: JSONValue?
            do {
                guard let keys = try await API(base: configuration.server).ownKeys(token: login.token) else {
                    throw SafetyError.deviceIdentityReplaced
                }
                guard fatalError == nil, let latest = account else { throw SafetyError.persistence }
                let validated: CoreResult
                do { validated = try core.call("validate_registered_keys", state: latest.core, fields: ["keys": keys]) }
                catch is CoreError { throw SafetyError.deviceIdentityReplaced }
                validatedState = validated.state
                resolvedMessageIDs = validated.resolved_message_ids ?? []
                if snapshot?.key_maintenance.initial_upload_pending == true {
                    guard let state = validatedState else { throw SafetyError.persistence }
                    let confirmation = try core.call("confirm_initial_upload", state: state)
                    validatedState = confirmation.state
                    resolvedMessageIDs += confirmation.resolved_message_ids ?? []
                }
            } catch SafetyError.deviceIdentityReplaced {
                try lockChangedRegistration()
                throw SafetyError.deviceIdentityReplaced
            }
            guard fatalError == nil, let latest = account else { throw SafetyError.persistence }
            guard let validatedState else { throw SafetyError.persistence }
            proposed = latest
            proposed.core = validatedState
            proposed.registered = true
            proposed.token = login.token
            proposed.expiresAt = login.expires_at
        } else {
            // Google sign-in does not restore another device's private keys.
            // Check before generating or saving any new local identity. The
            // server's immutable key registration still protects an upload race.
            try await API(base: configuration.server).requireUnregisteredIdentity(token: login.token)
            let result = try core.call("init", fields: ["email": .string(login.email)])
            guard let state = result.state else { throw CoreError.rejected }
            proposed = StoredAccount(version: 1, backend: configuration.server.absoluteString, email: login.email,
                                     token: login.token, expiresAt: login.expires_at, core: state, registered: false)
        }
        try persist(proposed, resolvedMessageIDs: resolvedMessageIDs)
        needsAuthentication = false
    }

    func addContact(_ input: String) async {
        await run {
            let email = try MessageSafety.canonicalEmail(input)
            let (account, api) = try authenticated()
            guard email != account.email else { throw SafetyError.selfContact }
            if snapshot?.contacts.contains(where: { $0.email == email }) == true { return }
            let bundle = try await api.claim(email: email, token: account.token)
            // Expiry/read maintenance can run while the lookup is awaiting I/O.
            guard fatalError == nil, let state = self.account?.core else { throw SafetyError.persistence }
            try apply(core.call("add_contact", state: state, fields: ["bundle": bundle]))
        }
    }

    func verifyContact(email: String, fingerprint: String) async {
        await run {
            let (account, _) = try authenticated()
            // Whitespace removal is only for a manually pasted fingerprint;
            // message text is never normalized or filtered.
            let value = fingerprint.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "").lowercased()
            guard MessageSafety.validFingerprint(value) else { throw SafetyError.invalidResponse }
            try apply(core.call("verify_contact", state: account.core, fields: ["email": .string(email), "fingerprint": .string(value)]))
            try await synchronize()
        }
    }

    func removeContact(_ request: ContactRemoval) async -> ContactRemovalResult {
        guard !busy, fatalError == nil, operationIntent == nil else { return .failed("ISYEET is busy or unavailable. Try again when it is ready.") }
        busy = true
        defer { busy = false }
        do {
            try maintain()
            try request.validate(current: snapshot?.contacts.first { $0.email == request.email })
            guard let state = account?.core else { throw SafetyError.persistence }
            try apply(core.call("remove_contact", state: state, fields: [
                "email": .string(request.email), "previous_fingerprint": .string(request.previousFingerprint),
            ]), clearIdentityChangeFor: request.email)
        } catch { return .failed(safeDescription(error)) }
        do {
            let (current, api) = try authenticated()
            try await api.syncContacts(emails: snapshot?.contacts.filter(\.verified).map(\.email) ?? [], token: current.token)
            return .removed
        } catch {
            if error as? SafetyError == .unauthorized { needsAuthentication = true }
            return .removedPendingSynchronization
        }
    }

    func send(text: String, recipient: String) async -> Bool {
        guard !busy, fatalError == nil, !updatingContactVerification else { return false }
        busy = true
        defer { busy = false }
        do {
            try MessageSafety.validate(text)
            guard !pendingIdentityChanges.contains(recipient) else { throw CoreError.identityChanged }
            let (account, _) = try authenticated()
            try apply(core.call("encrypt", state: account.core, fields: ["recipient": .string(recipient), "text": .string(text)]))
            // Encryption and the pending envelope are now durable. A network
            // failure leaves the exact same id and ciphertext available to retry.
            do { try await synchronize() } catch { report(error) }
            return true
        } catch { report(error); return false }
    }

    func groupIsBlocked(_ groupID: String) -> Bool {
        guard let snapshot, let group = snapshot.groups.first(where: { $0.id == groupID }) else { return true }
        return group.blocked || group.members.contains { member in
            guard member.email != snapshot.email else { return member.fingerprint != snapshot.fingerprint }
            return pendingIdentityChanges.contains(member.email)
                || !snapshot.contacts.contains { $0.email == member.email && $0.fingerprint == member.fingerprint && $0.verified }
        }
    }

    func createGroup(title: String, members: [String]) async -> String? {
        guard !busy, fatalError == nil, !updatingContactVerification else { return nil }
        busy = true
        defer { busy = false }
        do {
            try MessageGroup.validateTitle(title)
            let (current, _) = try authenticated()
            guard (1...7).contains(members.count), Set(members).count == members.count,
                  members.allSatisfy({ email in
                      email != current.email && !pendingIdentityChanges.contains(email)
                          && snapshot?.contacts.contains(where: { $0.email == email && $0.verified }) == true
                  }) else { throw SafetyError.invalidGroup }
            let result = try core.call("create_group", state: current.core, fields: [
                "title": .string(title), "members": .array(members.sorted().map(JSONValue.string)),
            ])
            guard let group = try result.data?.decoded(MessageGroup.self) else { throw CoreError.rejected }
            try apply(result)
            return group.id
        } catch { report(error); return nil }
    }

    func sendGroup(text: String, groupID: String) async -> Bool {
        guard !busy, fatalError == nil, !updatingContactVerification else { return false }
        busy = true
        defer { busy = false }
        do {
            try MessageSafety.validate(text)
            let (current, _) = try authenticated()
            guard !groupIsBlocked(groupID) else { throw CoreError.groupVerificationRequired }
            // The core proposes every pairwise Signal envelope atomically.
            // One Keychain write precedes the first network request.
            try apply(core.call("encrypt_group", state: current.core, fields: ["group_id": .string(groupID), "text": .string(text)]))
            do { try await synchronize() } catch { report(error) }
            return true
        } catch { report(error); return false }
    }

    func refresh(quiet: Bool = false) async {
        maintainLocalMessages()
        guard !needsAuthentication, fatalError == nil, !updatingContactVerification else { return }
        await run(quiet: quiet) { try await synchronize() }
    }

    private func run(quiet: Bool = false, _ body: () async throws -> Void) async {
        guard !busy, fatalError == nil, operationIntent == nil, !updatingContactVerification else { return }
        busy = true
        defer { busy = false }
        do { try await body() }
        catch {
            if error as? SafetyError == .unauthorized { needsAuthentication = true }
            if !quiet || error is CoreError || error as? SafetyError == .invalidResponse || error as? SafetyError == .persistence { report(error) }
        }
    }

    func updatePushToken(_ deviceToken: String?) async throws {
        let (account, api) = try authenticated()
        try await api.updatePushToken(deviceToken, token: account.token)
    }

    private func authenticated() throws -> (StoredAccount, API) {
        guard fatalError == nil, operationIntent == nil, account?.identityReplaced != true else { throw SafetyError.persistence }
        try maintain()
        guard let account, let configuration,
              account.expiresAt > Int64(Date().timeIntervalSince1970) else { throw SafetyError.unauthorized }
        return (account, API(base: configuration.server))
    }

    private func maintainRegisteredKeys(_ api: API, token: String) async throws {
        if snapshot?.key_maintenance.pending == nil,
           let checkAt = snapshot?.key_maintenance.next_check_at,
           checkAt <= Int64(Date().timeIntervalSince1970) {
            let inventory = try await api.keyMaintenanceInventory(token: token)
            guard fatalError == nil, operationIntent == nil, let latest = account else { throw SafetyError.persistence }
            // Use the latest ratchet/expiry state after the network await.
            try apply(core.call("prepare_key_maintenance", state: latest.core, fields: ["inventory": inventory]))
        }
        guard let pending = snapshot?.key_maintenance.pending else { return }
        // The complete private proposal and exact retry request are already saved.
        // Retry it before fetching inventory; never regenerate after a lost reply.
        let receipt = try await api.maintainKeys(pending, token: token)
        guard fatalError == nil, operationIntent == nil, let latest = account else { throw SafetyError.persistence }
        try apply(core.call("confirm_key_maintenance", state: latest.core, fields: ["receipt": receipt]))
    }

    private func synchronize() async throws {
        var (current, api) = try authenticated()
        if !current.registered {
            let confirmation: CoreResult
            if snapshot?.key_maintenance.initial_upload_pending == true {
                let upload = try core.call("key_upload", state: current.core)
                guard let keys = upload.data else { throw CoreError.rejected }
                try apply(upload)
                try await api.upload(keys: keys, token: current.token)
                guard fatalError == nil, let latest = account else { throw SafetyError.persistence }
                confirmation = try core.call("confirm_initial_upload", state: latest.core)
            } else {
                // A migrated wrapper with an uncertain old upload may validate
                // an existing registration, but must never publish old keys.
                do {
                    guard let keys = try await api.ownKeys(token: current.token) else { throw SafetyError.deviceIdentityReplaced }
                    guard fatalError == nil, let latest = account else { throw SafetyError.persistence }
                    do { confirmation = try core.call("validate_registered_keys", state: latest.core, fields: ["keys": keys]) }
                    catch is CoreError { throw SafetyError.deviceIdentityReplaced }
                } catch SafetyError.deviceIdentityReplaced {
                    try lockChangedRegistration()
                    throw SafetyError.deviceIdentityReplaced
                }
            }
            // Core registration acknowledgement and wrapper flag share a write.
            guard var registered = account, let confirmedState = confirmation.state else { throw SafetyError.persistence }
            registered.core = confirmedState
            registered.registered = true
            try persist(registered, resolvedMessageIDs: confirmation.resolved_message_ids ?? [])
            current = registered
        }
        // Only independently verified contacts may place ciphertext in this
        // account's relay queue. Retry this idempotent update after a crash.
        try await api.syncContacts(emails: snapshot?.contacts.filter(\.verified).map(\.email) ?? [], token: current.token)
        try await reconcileTrafficMode(api, token: current.token)
        var deliveryFailed = false
        // Cover mode has exactly one sender: the independent slot scheduler.
        // Sign-in, send, refresh, retry and notification taps can only fetch.
        for id in trafficMode == .notifications ? (snapshot?.outbox.map(\.id) ?? []) : [] {
            try maintain()
            // Never reuse a captured envelope after an await: its deadline may
            // have passed while another delivery was pending.
            guard let outgoing = snapshot?.outbox.first(where: { $0.id == id }) else { continue }
            guard trafficMode == .notifications, outgoingAllowed(outgoing) else { continue }
            do {
                try await api.send(outgoing, token: current.token)
            } catch {
                // One unavailable/full/unverified recipient must not starve
                // unrelated outgoing messages or the whole incoming queue.
                if let safety = error as? SafetyError, safety != .network { throw error }
                if error is CoreError { throw error }
                deliveryFailed = true
                continue
            }
            guard let state = account?.core else { throw SafetyError.persistence }
            try apply(core.call("sent", state: state, fields: ["id": .string(outgoing.id)]))
        }
        let messages: [QueuedMessage]
        checkingInbox = true
        do { messages = try await api.inbox(token: current.token) }
        catch { checkingInbox = false; throw error }
        checkingInbox = false
        guard fatalError == nil else { throw SafetyError.persistence }
        var unverified = Set<String>()
        for incoming in messages {
            guard UUID(uuidString: incoming.id) != nil,
                  try MessageSafety.canonicalEmail(incoming.sender) == incoming.sender else { throw SafetyError.invalidResponse }
            guard let state = account?.core else { throw SafetyError.persistence }
            let wire = try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(incoming))
            do {
                let result = try core.call("decrypt", state: state, fields: ["message": wire])
                guard let data = result.data else { throw SafetyError.invalidResponse }
                let message = try data.decoded(StoredMessage.self)
                try apply(result, arrival: message)
                if !message.expired && !message.cover && message.security_alert != nil {
                    alert = "Security alert: an invalid message was rejected."
                }
                // Durable inbox+ratchet+dedupe+unread storage has completed above.
                try await api.acknowledge(incoming.id, token: current.token)
            } catch CoreError.verificationRequired {
                unverified.insert(incoming.sender)
            } catch CoreError.groupVerificationRequired {
                unverified.insert(incoming.sender)
                alert = CoreError.groupVerificationRequired.errorDescription
            } catch CoreError.groupCapacityReached {
                unverified.insert(incoming.sender)
                alert = CoreError.groupCapacityReached.errorDescription
            } catch CoreError.identityChanged {
                guard var proposed = account,
                      let contact = snapshot?.contacts.first(where: { $0.email == incoming.sender }) else { throw SafetyError.invalidResponse }
                observedIdentityChanges[contact.email] = contact.fingerprint
                if !proposed.contactIdentityChanges.contains(incoming.sender) {
                    proposed.contactIdentityChanges.append(incoming.sender)
                    do {
                        let result = try core.call("block_groups_for_contact", state: proposed.core, fields: ["email": .string(incoming.sender)])
                        guard let state = result.state else { throw SafetyError.persistence }
                        proposed.core = state
                        try persist(proposed, resolvedMessageIDs: result.resolved_message_ids ?? [])
                    } catch { hideMessagesAfterMaintenanceFailure(error); throw error }
                }
                // No ACK: the new identity remains untrusted until the person
                // explicitly supplies and confirms their new fingerprint.
            }
        }
        pendingUnverified = unverified.sorted()
        // A full page or unverified ciphertext may leave unseen messages on
        // the relay. Preserve its generic hint until a later poll catches up.
        // An unrelated outgoing failure does not prevent reconciliation.
        if messages.count < API.inboxPageSize && unverified.isEmpty && pendingIdentityChanges.isEmpty && snapshot?.pending_group_senders.isEmpty == true {
            synchronizationSequence &+= 1
        }
        // Inventory limits or an unavailable maintenance endpoint must not
        // starve authenticated incoming messages or their durable ACKs.
        try await maintainRegisteredKeys(api, token: current.token)
        if deliveryFailed { throw SafetyError.network }
    }

    private func apply(_ result: CoreResult, arrival: StoredMessage? = nil, clearIdentityChangeFor email: String? = nil, resolvedMessageIDs: [String] = []) throws {
        guard fatalError == nil, var proposed = account, let state = result.state else { throw SafetyError.persistence }
        proposed.core = state
        if let email { proposed.contactIdentityChanges.removeAll { $0 == email } }
        try persist(proposed, arrival: arrival, resolvedMessageIDs: resolvedMessageIDs + (result.resolved_message_ids ?? []), ignoringIdentityChangeFor: email)
    }

    private func persist(_ value: StoredAccount, arrival: StoredMessage? = nil, recovering: Bool = false, resolvedMessageIDs: [String] = [], ignoringIdentityChangeFor removedEmail: String? = nil) throws {
        guard fatalError == nil || recovering else { throw SafetyError.persistence }
        var proposed = value
        var resolvedIDs = Set(resolvedMessageIDs)
        // Reconcile warnings before any expiry call can promote quarantined
        // group text, including a new group whose sender is another member.
        for email in Set(proposed.contactIdentityChanges) {
            let result = try core.call("block_groups_for_contact", state: proposed.core, fields: ["email": .string(email)])
            guard let state = result.state else { throw SafetyError.persistence }
            proposed.core = state
            resolvedIDs.formUnion(result.resolved_message_ids ?? [])
        }
        for (email, pin) in observedIdentityChanges where email != removedEmail {
            // A replacement may already have committed before a later save
            // failed. Never carry the old warning onto that newer identity.
            let result = try core.call("block_groups_for_contact", state: proposed.core,
                                       fields: ["email": .string(email), "fingerprint": .string(pin)])
            guard let state = result.state else { throw SafetyError.persistence }
            proposed.core = state
            resolvedIDs.formUnion(result.resolved_message_ids ?? [])
        }
        var expired = try core.expire(proposed.core)
        resolvedIDs.formUnion(expired.snapshot.resolved_message_ids)
        var now = Int64(Date().timeIntervalSince1970)
        // A deadline can pass between the core call and the Swift clock sample.
        // Re-run against the proposed state until all due records are durably
        // removed; never just filter a view and lose the next cleanup deadline.
        while let next = expired.snapshot.nextExpiry, next <= now {
            let previous = expired.state
            expired = try core.expire(expired.state)
            resolvedIDs.formUnion(expired.snapshot.resolved_message_ids)
            guard expired.state != previous else {
                throw SafetyError.invalidResponse
            }
            now = Int64(Date().timeIntervalSince1970)
        }
        proposed.core = expired.state
        let display = expired.snapshot
        guard display.email == proposed.email else { throw SafetyError.invalidResponse }
        // If recording a warning failed, explicit reload must still preserve
        // that conservative block until the corresponding pin is replaced.
        for (email, pin) in observedIdentityChanges where email != removedEmail && display.contacts.contains(where: { $0.email == email && $0.fingerprint == pin }) {
            proposed.contactIdentityChanges.append(email)
        }
        proposed.contactIdentityChanges = Array(Set(proposed.contactIdentityChanges)).filter { email in
            display.contacts.contains { $0.email == email }
        }.sorted()
        proposed.unreadMessageIDs = UnreadMessages.updatedIDs(proposed.unreadMessageIDs, snapshot: display,
                                                             arrival: arrival, arrivals: display.messages.filter { resolvedIDs.contains($0.id) }, reading: currentReadContext, now: now)
        let newUnread = Set(proposed.unreadMessageIDs).subtracting(account?.unreadMessageIDs ?? [])
        let retainedUnread = UnreadMessages.updatedIDs(value.unreadMessageIDs, snapshot: display,
                                                       reading: MessageReadContext(), now: now)
        let expiredUnread = Set(value.unreadMessageIDs).subtracting(retainedUnread).isEmpty == false
        // Avoid a Keychain write every foreground poll when nothing changed.
        if proposed != account { try vault.save(proposed) }
        // The removal is now durable, even if a later expiry write fails.
        // A reload must not replay an observed warning against a missing pin.
        if let removedEmail { observedIdentityChanges.removeValue(forKey: removedEmail) }
        if let deadline = display.nextExpiry, deadline <= Int64(Date().timeIntervalSince1970) {
            // Keychain itself can take us across a deadline. Save the newly
            // pruned proposal before publishing any result of that slow write.
            do { try persist(proposed, arrival: arrival, recovering: recovering, resolvedMessageIDs: Array(resolvedIDs), ignoringIdentityChangeFor: removedEmail) }
            catch {
                // The first write succeeded. Require a reload of that durable
                // state rather than continuing with an older in-memory ratchet.
                hideMessagesAfterMaintenanceFailure(error)
                throw error
            }
            return
        }
        account = proposed
        snapshot = display
        pendingIdentityChanges = proposed.contactIdentityChanges
        observedIdentityChanges = observedIdentityChanges.filter { email, pin in
            display.contacts.contains { $0.email == email && $0.fingerprint == pin }
        }
        unreadCounts = UnreadMessages.counts(proposed.unreadMessageIDs, snapshot: display, now: now)
        // Notifications can observe this only after the same durable save as the inbox.
        if (arrival != nil || !resolvedIDs.isEmpty) && !newUnread.isEmpty {
            unreadArrivalSequence &+= 1
            showsNewMessageIndicator = true
        }
        if unreadCount == 0 { showsNewMessageIndicator = false }
        if expiredUnread { retentionSequence &+= 1 }
        scheduleExpiry()
        scheduleCoverTraffic()
        writeSimulatorTestReport()
    }

    private func writeSimulatorTestReport() {
        #if DEBUG && targetEnvironment(simulator)
        guard configuration?.simulatorDevelopmentEmail != nil, let snapshot,
              let expected = ProcessInfo.processInfo.environment["ISYEET_SIMULATOR_EXPECT_TEXT"] else { return }
        // Test assertion only: export booleans/counts, never keys, state, or text.
        let report: [String: JSONValue] = [
            "received_expected_text": .bool(snapshot.messages.contains { $0.sender != snapshot.email && $0.text == expected }),
            "pending_outbox_count": .integer(Int64(snapshot.outbox.count)),
            "security_alert_count": .integer(Int64(snapshot.messages.filter { $0.security_alert != nil }.count)),
        ]
        let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("simulator-test-result.json")
        try? JSONEncoder().encode(report).write(to: url, options: .atomic)
        #endif
    }

    private func report(_ error: Error) {
        switch error {
        case CoreError.coverClockUnavailable, CoreError.coverUnavailable:
            trafficIssue = safeDescription(error)
            return
        default: break
        }
        if error as? SafetyError == .unauthorized { needsAuthentication = true }
        alert = safeDescription(error)
    }

    private func safeDescription(_ error: Error) -> String {
        if let error = error as? SafetyError { return error.errorDescription! }
        if let error = error as? CoreError { return error.errorDescription! }
        return SafetyError.network.errorDescription!
    }
}
