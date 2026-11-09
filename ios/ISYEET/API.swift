import Foundation

// Reject redirects so neither a bearer token nor an authentication proof can
// be forwarded to an endpoint other than the one the app selected.
final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

enum Network {
    static let maximumResponseBytes = 2 * 1024 * 1024
    static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        return URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
    }()

    static func boundedData(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse,
              response.expectedContentLength <= maximumResponseBytes else { throw SafetyError.invalidResponse }
        var data = Data()
        for try await byte in bytes {
            guard data.count < maximumResponseBytes else { throw SafetyError.invalidResponse }
            data.append(byte)
        }
        return (data, http)
    }
}

struct LoginResponse: Decodable {
    let token: String
    let account_id: String
    let username: String
    let expires_at: Int64
}

struct API {
    static let inboxPageSize = 50
    let base: URL

    func deviceAuthority(token: String) async throws -> DeviceAuthorityResponse {
        guard DeviceAuthorizationFeature.enabled, base.absoluteString == "https://api-staging.isyeet.io" else { throw SafetyError.deviceAuthorizationUnavailable }
        let data = try await request("v3/devices/authority", method: "GET", token: token)
        return try JSONDecoder().decode(DeviceAuthorityResponse.self, from: data).validated()
    }

    func changeDeviceAuthority(_ change: JSONValue, token: String, actionToken: String) async throws -> DeviceAuthorityReceipt {
        guard DeviceAuthorizationFeature.enabled, base.absoluteString == "https://api-staging.isyeet.io" else { throw SafetyError.deviceAuthorizationUnavailable }
        let data = try await request("v3/devices/authority", method: "PUT", token: token,
                                    body: .object(["action_token": .string(actionToken), "change": change]))
        return try JSONDecoder().decode(DeviceAuthorityReceipt.self, from: data).validated()
    }

    func registrationStart(username: String) async throws -> PasskeyChallenge {
        try await challenge("v2/auth/register/start", body: .object(["username": .string(username)]))
    }
    func loginStart() async throws -> PasskeyChallenge {
        try await challenge("v2/auth/login/start", body: .object([:]))
    }
    func loginFinish(challengeID: String, credential: JSONValue, registering: Bool) async throws -> LoginResponse {
        let data = try await request("v2/auth/" + (registering ? "register" : "login") + "/finish", method: "POST",
            body: .object(["challenge_id": .string(challengeID), "credential": credential]))
        return try validateLogin(data)
    }
    func reauthenticationStart(token: String, purpose: String) async throws -> PasskeyChallenge {
        try await challenge("v2/auth/reauth/start", token: token, body: .object(["purpose": .string(purpose)]))
    }
    func reauthenticationFinish(token: String, challengeID: String, credential: JSONValue) async throws -> PasskeyAction {
        let data = try await request("v2/auth/reauth/finish", method: "POST", token: token,
            body: .object(["challenge_id": .string(challengeID), "credential": credential]))
        let action = try JSONDecoder().decode(PasskeyAction.self, from: data)
        guard !action.action_token.isEmpty, action.action_token.utf8.count <= 1024,
              action.action_token.utf8.allSatisfy({ (0x21...0x7e).contains($0) }),
              action.expires_at > Int64(Date().timeIntervalSince1970) else { throw SafetyError.invalidResponse }
        return action
    }
    func passkeys(token: String) async throws -> [RegisteredPasskey] {
        let data = try await request("v2/passkeys", method: "GET", token: token)
        let result = try JSONDecoder().decode(PasskeyList.self, from: data)
        guard result.maximum == 8, (1...8).contains(result.passkeys.count),
              Set(result.passkeys.map(\.id)).count == result.passkeys.count,
              result.passkeys.allSatisfy({ Data(base64URL: $0.id) != nil && (1...32).contains($0.label.utf8.count)
                  && $0.label.utf8.allSatisfy({ (0x20...0x7e).contains($0) }) && $0.created_at > 0 }) else { throw SafetyError.invalidResponse }
        return result.passkeys
    }
    func addPasskeyStart(token: String, actionToken: String, label: String) async throws -> PasskeyChallenge {
        try await challenge("v2/passkeys/add/start", token: token,
                            body: .object(["action_token": .string(actionToken), "label": .string(label)]))
    }
    func addPasskeyFinish(token: String, challengeID: String, credential: JSONValue) async throws {
        _ = try await request("v2/passkeys/add/finish", method: "POST", token: token,
            body: .object(["challenge_id": .string(challengeID), "credential": credential]))
    }
    func removePasskey(id: String, token: String, actionToken: String) async throws {
        guard Data(base64URL: id) != nil else { throw SafetyError.invalidResponse }
        _ = try await request("v2/passkeys/" + id, method: "DELETE", token: token, body: .object(["action_token": .string(actionToken)]))
    }
    private func challenge(_ path: String, token: String? = nil, body: JSONValue) async throws -> PasskeyChallenge {
        let data = try await request(path, method: "POST", token: token, body: body)
        let challenge = try JSONDecoder().decode(PasskeyChallenge.self, from: data)
        guard AccountStateResponse.canonicalGeneration(challenge.challenge_id) else { throw SafetyError.invalidResponse }
        return challenge
    }
    func lookup(username: String, token: String) async throws -> DirectoryAccount {
        let data = try await request("v2/directory/lookup", method: "POST", token: token, body: .object(["username": .string(username)]))
        let account = try JSONDecoder().decode(DirectoryAccount.self, from: data).validated()
        guard account.username == username else { throw SafetyError.invalidResponse }
        return account
    }

    private func validateLogin(_ response: Data) throws -> LoginResponse {
        let login = try JSONDecoder().decode(LoginResponse.self, from: response)
        guard try MessageSafety.canonicalAccountID(login.account_id) == login.account_id,
              try MessageSafety.canonicalUsername(login.username) == login.username,
              !login.token.isEmpty, login.token.utf8.count <= 1024,
              login.token.utf8.allSatisfy({ (0x21...0x7e).contains($0) }),
              login.expires_at > Int64(Date().timeIntervalSince1970) else { throw SafetyError.invalidResponse }
        return login
    }

    func claim(account_id: String, token: String) async throws -> JSONValue {
        let response = try await request("v2/keys/claim", method: "POST", token: token, body: .object(["account_id": .string(account_id)]))
        let bundle = try JSONDecoder().decode(JSONValue.self, from: response)
        guard case .object(let fields) = bundle, fields["account_id"] == .string(account_id) else { throw SafetyError.invalidResponse }
        return bundle
    }

    func accountState(token: String, account_id: String) async throws -> AccountStateResponse? {
        let (data, response) = try await response("v2/account/state", method: "GET", token: token)
        if response.statusCode == 404 {
            guard (try? JSONDecoder().decode([String: String].self, from: data)) == ["error": "not found"] else { throw SafetyError.invalidResponse }
            return nil
        }
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        guard response.statusCode == 200 else { throw SafetyError.network }
        return try JSONDecoder().decode(AccountStateResponse.self, from: data).validated(account_id: account_id)
    }

    func accountState(actionToken: String, account_id: String) async throws -> AccountStateResponse? {
        let (data, response) = try await response("v2/account/state", method: "POST", body: .object(["action_token": .string(actionToken)]))
        if response.statusCode == 404 {
            guard (try? JSONDecoder().decode([String: String].self, from: data)) == ["error": "not found"] else { throw SafetyError.invalidResponse }
            return nil
        }
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        guard response.statusCode == 200 else { throw SafetyError.network }
        return try JSONDecoder().decode(AccountStateResponse.self, from: data).validated(account_id: account_id)
    }

    func performAccountOperation(_ operation: AccountOperation) async throws {
        let (data, response) = try await response("v2/account/" + operation.kind.rawValue, method: "POST", body: operation.request())
        if response.statusCode == 404 {
            guard (try? JSONDecoder().decode([String: String].self, from: data)) == ["error": "not found"] else { throw SafetyError.invalidResponse }
            throw SafetyError.accountOperationConflict
        }
        if response.statusCode == 409 { throw SafetyError.accountOperationConflict }
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        guard response.statusCode == 200 else { throw SafetyError.network }
        try JSONDecoder().decode(AccountCompletion.self, from: data).validate(operation)
    }

    func keyMaintenanceInventory(token: String) async throws -> JSONValue {
        let data = try await request("v2/keys/maintenance", method: "GET", token: token)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    func maintainKeys(_ pending: JSONValue, token: String) async throws -> JSONValue {
        let data = try await request("v2/keys/maintenance", method: "PUT", token: token, body: pending)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    func ownKeys(token: String) async throws -> JSONValue? {
        let (data, response) = try await response("v2/keys/me", method: "GET", token: token)
        if response.statusCode == 404 {
            guard (try? JSONDecoder().decode([String: String].self, from: data)) == ["error": "not found"] else { throw SafetyError.invalidResponse }
            return nil
        }
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        guard response.statusCode == 200 else { throw SafetyError.network }
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    func requireUnregisteredIdentity(token: String) async throws {
        let (data, response) = try await response("v2/keys/me", method: "GET", token: token)
        try AccountRegistration.requireUnregistered(statusCode: response.statusCode, body: data)
    }

    func upload(keys: JSONValue, token: String) async throws {
        _ = try await request("v2/keys", method: "PUT", token: token, body: keys)
    }

    func syncContacts(account_ids: [String], token: String) async throws {
        _ = try await request("v2/contacts", method: "PUT", token: token,
                              body: .object(["account_ids": .array(account_ids.map(JSONValue.string))]))
    }

    func send(_ envelope: SendRequest, token: String) async throws {
        _ = try await request("v2/messages", method: "POST", token: token, encodedBody: MessageTransport.paddedBody(envelope))
    }

    func trafficMode(token: String, allowLegacy: Bool) async throws -> TrafficModeResponse? {
        let (data, response) = try await response("v2/traffic-mode", method: "GET", token: token)
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        if response.statusCode == 404 && allowLegacy { return nil }
        guard response.statusCode == 200 else { throw SafetyError.trafficUnavailable }
        return try JSONDecoder().decode(TrafficModeResponse.self, from: data).validated()
    }

    func setTrafficMode(cover: Bool, token: String) async throws -> TrafficModeResponse {
        let data = try await request("v2/traffic-mode", method: "PUT", token: token, body: .object(["cover": .bool(cover)]))
        let mode = try JSONDecoder().decode(TrafficModeResponse.self, from: data).validated()
        guard mode.cover == cover else { throw SafetyError.invalidResponse }
        return mode
    }

    func inbox(token: String) async throws -> [QueuedMessage] {
        struct Response: Decodable { let messages: [QueuedMessage] }
        let data = try await request("v2/messages?limit=\(Self.inboxPageSize)", method: "GET", token: token)
        let messages = try JSONDecoder().decode(Response.self, from: data).messages
        guard messages.count <= Self.inboxPageSize else { throw SafetyError.invalidResponse }
        return messages
    }

    func acknowledge(_ id: String, token: String) async throws {
        _ = try await request("v2/messages/ack", method: "POST", token: token, body: .object(["ids": .array([.string(id)])]))
    }

    func updatePushToken(_ deviceToken: String?, token: String) async throws {
        if let deviceToken {
            _ = try await request("v2/push-token", method: "PUT", token: token,
                                  body: .object(["token": .string(deviceToken)]))
        } else {
            _ = try await request("v2/push-token", method: "DELETE", token: token)
        }
    }

    private func request(_ path: String, method: String, token: String? = nil, body: JSONValue? = nil, encodedBody: Data? = nil) async throws -> Data {
        let (data, response) = try await response(path, method: method, token: token, body: body, encodedBody: encodedBody)
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        if response.statusCode == 409, path == "v3/devices/authority" { throw SafetyError.deviceAuthorizationConflict }
        if response.statusCode == 409, (path == "v2/auth/register/start" || path == "v2/auth/register/finish") { throw SafetyError.usernameUnavailable }
        guard (200...299).contains(response.statusCode) else { throw SafetyError.network }
        return data
    }

    private func response(_ path: String, method: String, token: String? = nil,
                          body: JSONValue? = nil, encodedBody: Data? = nil) async throws -> (Data, HTTPURLResponse) {
        guard let url = URL(string: "/" + path, relativeTo: base)?.absoluteURL else { throw SafetyError.configuration }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        if let encodedBody = try encodedBody ?? body.map({ try JSONEncoder().encode($0) }) {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = encodedBody
        }
        return try await Network.boundedData(for: request)
    }
}
