import Combine
import UIKit
import UserNotifications

// Push notifications are generic delivery hints. Never decode ciphertext,
// inspect payload identifiers, or include contact/message data in an alert.
@MainActor
final class PushNotifications: NSObject, ObservableObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    @Published private(set) var authorization: UNAuthorizationStatus = .notDetermined
    @Published private(set) var issue: String?
    @Published private(set) var enabling = false

    private weak var model: AppModel?
    private var deviceToken: String?
    private var registeredToken: String?
    private var tokenRevision: UInt64 = 0
    private var registeredRevision: UInt64?
    private var removalSynchronized = false
    private var synchronizing = false
    private var nextRegistrationAttempt = Date.distantPast
    private var pendingInbox = false
    private var badgeTarget: (count: Int, preserveRemoteHint: Bool)?
    private var updatingBadge = false
    private var unreconciledRemoteHint = false

    var allowed: Bool { [.authorized, .provisional, .ephemeral].contains(authorization) }

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func attach(_ model: AppModel) {
        self.model = model
        if pendingInbox { openInbox() }
    }

    func refreshAuthorization() async {
        authorization = await UNUserNotificationCenter.current().notificationSettings().authorizationStatus
        if allowed {
            UIApplication.shared.registerForRemoteNotifications()
        }
        await synchronizeRegistration()
    }

    func enable() async {
        guard !enabling else { return }
        enabling = true
        defer { enabling = false }
        issue = nil
        nextRegistrationAttempt = .distantPast
        do {
            _ = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
            await refreshAuthorization()
        } catch {
            issue = "Notifications could not be enabled. Messages remain available in the app."
        }
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken token: Data) {
        let value = token.map { String(format: "%02x", $0) }.joined()
        guard (32...512).contains(value.count), value.count.isMultiple(of: 2) else {
            issue = "Notifications could not be enabled. Messages remain available in the app."
            return
        }
        deviceToken = value
        // Apple can freshly register the same token bytes after invalidation.
        tokenRevision &+= 1
        Task { await synchronizeRegistration() }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
        issue = "Notifications could not be enabled. Messages remain available in the app."
    }

    func synchronizeRegistration() async {
        guard !synchronizing, Date() >= nextRegistrationAttempt,
              let model, !model.needsAuthentication else { return }
        let desired = allowed ? deviceToken : nil
        let revision = tokenRevision
        let accountRevision = model.accountLifecycleSequence
        if allowed && desired == nil { return }
        if let desired, desired == registeredToken && revision == registeredRevision { return }
        if !allowed && removalSynchronized { return }
        synchronizing = true
        defer { synchronizing = false }
        do {
            try await model.updatePushToken(desired)
            guard model.accountLifecycleSequence == accountRevision else {
                Task { await synchronizeRegistration() }
                return
            }
            registeredToken = desired
            registeredRevision = desired == nil ? nil : revision
            removalSynchronized = desired == nil
            issue = nil
            nextRegistrationAttempt = .distantPast
            if (allowed ? deviceToken : nil) != desired || (allowed && tokenRevision != revision) {
                // A callback during the PUT could not start another request.
                // Drain that newer registration as soon as this actor turn ends.
                Task { await synchronizeRegistration() }
            }
        } catch {
            nextRegistrationAttempt = Date().addingTimeInterval(60)
            if allowed {
                issue = "Notifications could not be enabled. Messages remain available in the app."
            }
        }
    }

    func accountDidChange() {
        registeredToken = nil
        registeredRevision = nil
        removalSynchronized = false
        nextRegistrationAttempt = .distantPast
        unreconciledRemoteHint = false
        pendingInbox = false
        Task { await updateBadge(0); await synchronizeRegistration() }
    }

    func updateBadge(_ count: Int, preservingRemoteHints: Bool = false) async {
        badgeTarget = (count, preservingRemoteHints)
        guard !updatingBadge else { return }
        updatingBadge = true
        defer { updatingBadge = false }
        while let update = badgeTarget {
            badgeTarget = nil
            let center = UNUserNotificationCenter.current()
            let delivered = update.preserveRemoteHint ? await center.deliveredNotifications() : []
            // A newer request supersedes an older query that was awaiting Apple.
            if badgeTarget != nil { continue }
            let target = NotificationBadge.count(unread: update.count,
                                                 preservingRemoteHint: update.preserveRemoteHint,
                                                 deliveredHint: !delivered.isEmpty || unreconciledRemoteHint)
            if !update.preserveRemoteHint { unreconciledRemoteHint = false }
            try? await UNUserNotificationCenter.current().setBadgeCount(target)
            if target == 0 && !update.preserveRemoteHint {
                UNUserNotificationCenter.current().removeAllDeliveredNotifications()
            }
        }
    }

    private func openInbox() {
        unreconciledRemoteHint = true
        guard let model else { pendingInbox = true; return }
        pendingInbox = false
        model.showInbox()
        Task { await model.refresh(quiet: true) }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        // Foreground hints can race with inbox fetches. Only the app's validated,
        // persisted unread state produces the in-app indicator.
        await rememberRemoteHint()
        return []
    }

    private func rememberRemoteHint() { unreconciledRemoteHint = true }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await openInbox()
    }
}
