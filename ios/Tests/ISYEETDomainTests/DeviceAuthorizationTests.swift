import Foundation
import Testing
@testable import ISYEETDomain

@Test func manualPairingRejectsControlsUnicodeWrongKindAndOversizeBeforeCore() throws {
    let valid = "ISYEET-LINK-1:" + Data(#"{"public":"synthetic"}"#.utf8).base64URL
    try DevicePairingText.validate(valid)
    for bad in ["", " " + valid, valid + "\n", valid + "=", valid + "🙂", "https://example.com/" + valid,
                valid.replacingOccurrences(of: "LINK", with: "APPROVAL"), "ISYEET-LINK-1:AB",
                "ISYEET-LINK-1:" + String(repeating: "A", count: 16_384)] {
        #expect(throws: SafetyError.invalidPairingRequest) { try DevicePairingText.validate(bad) }
    }
    for control in UInt8(0)...UInt8(32) {
        #expect(throws: SafetyError.invalidPairingRequest) { try DevicePairingText.validate(valid + String(UnicodeScalar(control))) }
    }
}

@Test func pairingReviewMustMatchAccountAndUnexpiredExactFingerprint() throws {
    let account = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let epoch = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    func review(_ id: String = account, label: String = "Test desktop", expiry: Int64 = 1300, hash: String = String(repeating: "a", count: 64), device: UInt32 = 2) -> DeviceLinkInspection {
        .init(label: label, device_id: device, identity_fingerprint: String(repeating: "b", count: 64), request_hash: hash,
              expires_at: expiry, account_id: id, root_epoch: epoch)
    }
    _ = try review().validated(accountID: account, now: 1000)
    _ = try review(expiry: 1360).validated(accountID: account, now: 1000) // Signed lifetime plus allowed clock skew.
    for bad in [review(epoch), review(label: " Desktop"), review(label: "Desk\ntop"), review(label: "😀"), review(expiry: 1000), review(expiry: 1361), review(hash: String(repeating: "A", count: 64)), review(device: 1), review(device: 128)] {
        #expect(throws: SafetyError.invalidPairingRequest) { try bad.validated(accountID: account, now: 1000) }
    }
}

@Test func authorityResponsesCannotClaimMessagingOrUseUntrustedClock() throws {
    _ = try DeviceAuthorityResponse(authority: nil, server_time: 1000, messaging_available: false).validated(now: 1000)
    for value in [DeviceAuthorityResponse(authority: nil, server_time: 1000, messaging_available: true),
                  DeviceAuthorityResponse(authority: nil, server_time: 939, messaging_available: false),
                  DeviceAuthorityResponse(authority: nil, server_time: 1061, messaging_available: false),
                  DeviceAuthorityResponse(authority: nil, server_time: Int64.min, messaging_available: false)] {
        #expect(throws: SafetyError.invalidResponse) { try value.validated(now: 1000) }
    }
    let receipt = DeviceAuthorityReceipt(operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", roster_version: 1, roster_hash: String(repeating: "a", count: 64), messaging_available: true)
    #expect(throws: SafetyError.invalidResponse) { try receipt.validated() }
}

@Test func signedRosterDisplayRejectsExtraDevicesAndHostileLabels() throws {
    let account = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    let origin = "https://api-staging.isyeet.io"
    let epoch = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    func member(_ id: UInt32, label: String = "Test device", accountID: String = account) -> DeviceRosterMember {
        .init(certificate: .init(account_id: accountID, root_epoch: epoch, device_id: id, identity_key: "synthetic", registration_id: 1, label: label, request_hash: String(repeating: "a", count: 64)), signature: "synthetic")
    }
    func roster(_ devices: [DeviceRosterMember], source: String = origin) -> DeviceSignedRoster {
        .init(roster: .init(origin: source, account_id: account, root_epoch: epoch, root_identity_key: "synthetic", version: 1,
                           previous_hash: String(repeating: "0", count: 64), highest_device_id: 3, issued_at: 1000, expires_at: 87_400, devices: devices), signature: "synthetic")
    }
    _ = try roster([member(1), member(2)]).validated(accountID: account, origin: origin)
    for bad in [roster([]), roster([member(2)]), roster([member(1), member(1)]), roster([member(1), member(2), member(3)]),
                roster([member(1), member(2, label: "bad\u{1b}label")]), roster([member(1)], source: "https://api.isyeet.io"),
                roster([member(1), member(2, accountID: epoch)])] {
        #expect(throws: SafetyError.invalidResponse) { try bad.validated(accountID: account, origin: origin) }
    }
}

@Test func ordinaryBuildKeepsDeviceAuthorizationDisabled() {
    #if !DEBUG || !ISYEET_DEVICE_AUTHORIZATION_EXPERIMENT
    #expect(!DeviceAuthorizationFeature.enabled)
    #endif
}
