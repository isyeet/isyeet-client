import Foundation

struct CoreResult: Decodable {
    let ok: Bool
    let state: JSONValue?
    let data: JSONValue?
    let error: String?
    let resolved_message_ids: [String]?
}

enum CoreError: Error, LocalizedError {
    case deviceAuthorityRestoreRequired, deviceAuthorityRejected, coverClockUnavailable, coverUnavailable, verificationRequired, groupVerificationRequired, groupCapacityReached, identityChanged, retiredIdentity, contactRemovalRejected, rejected
    var errorDescription: String? {
        switch self {
        case .deviceAuthorityRestoreRequired: "The server's device list does not match this phone's saved authorization. Device approvals are stopped. Do not erase the saved authorization to bypass this warning."
        case .deviceAuthorityRejected: "Device authorization was rejected. Check the complete request, matching fingerprints, automatic date and time, and the current device list before trying again."
        case .coverClockUnavailable: "Cover traffic is paused because the device clock could not be checked against the server. Use automatic date and time, then refresh."
        case .coverUnavailable: "Cover traffic is paused until a verified contact shares fresh consent and capacity is available."
        case .verificationRequired: "Verify this contact's fingerprint through a trusted channel before exchanging messages. Pending messages remain queued."
        case .groupVerificationRequired: "Every group member must independently verify every other member outside ISYEET. Pending group text stays hidden until verification succeeds."
        case .groupCapacityReached: "This device cannot store another group or pending group message. The message remains queued; existing groups are unchanged."
        case .retiredIdentity: "This is the retired key that triggered an identity warning. Remove the contact and independently verify a different key before restoring contact."
        case .contactRemovalRejected: "The contact was not removed. Close this screen and review the current saved contact before trying again."
        case .identityChanged: "This contact's encryption identity changed. Stop and check with them outside ISYEET. Remove the old contact, add them again, and independently verify the new fingerprint before exchanging messages."
        case .rejected: "Security alert: the encryption operation was rejected. No unverified message was displayed."
        }
    }
}

struct CryptoBridge {
    func call(_ operation: String, state: JSONValue? = nil, fields: [String: JSONValue] = [:]) throws -> CoreResult {
        var request = fields
        request["op"] = .string(operation)
        if let state { request["state"] = state }
        let encoded = try JSONEncoder().encode(JSONValue.object(request))
        guard encoded.count <= 8 * 1024 * 1024,
              let string = String(data: encoded, encoding: .utf8),
              let pointer = string.withCString({ isyeet_call($0) }) else { throw CoreError.rejected }
        defer { isyeet_free_string(pointer) }
        // The pointer originates from the bundled core, never from a network peer.
        let result = try JSONDecoder().decode(CoreResult.self, from: Data(String(cString: pointer).utf8))
        guard result.ok else {
            if result.error == "device_authority_restore_required" { throw CoreError.deviceAuthorityRestoreRequired }
            if operation.hasPrefix("device_authority_") { throw CoreError.deviceAuthorityRejected }
            if operation == "remove_contact" { throw CoreError.contactRemovalRejected }
            if result.error == "cover_clock_unavailable" { throw CoreError.coverClockUnavailable }
            if result.error == "cover_unavailable" { throw CoreError.coverUnavailable }
            if result.error == "contact_verification_required" { throw CoreError.verificationRequired }
            if result.error == "contact_identity_removed" { throw CoreError.retiredIdentity }
            if result.error == "contact_identity_changed" { throw CoreError.identityChanged }
            if result.error == "group_verification_required" { throw CoreError.groupVerificationRequired }
            if result.error == "group_capacity_reached" { throw CoreError.groupCapacityReached }
            throw CoreError.rejected
        }
        guard result.state != nil else { throw CoreError.rejected }
        return result
    }

    func expire(_ state: JSONValue) throws -> (state: JSONValue, snapshot: Snapshot) {
        let result = try call("expire", state: state)
        guard let state = result.state, let data = result.data else { throw CoreError.rejected }
        return (state, try data.decoded(Snapshot.self).validated())
    }
}
