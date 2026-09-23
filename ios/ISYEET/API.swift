import Foundation

// Reject redirects so neither a bearer token nor a Google authorization code can
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
    let email: String
    let expires_at: Int64
}

struct API {
    static let inboxPageSize = 50
    let base: URL

    func login(idToken: String) async throws -> LoginResponse {
        let response = try await request("v1/auth/google", method: "POST", body: .object(["id_token": .string(idToken)]))
        return try validateLogin(response)
    }

    #if DEBUG && targetEnvironment(simulator)
    func simulatorDevelopmentLogin(email: String) async throws -> LoginResponse {
        guard base.scheme == "http", ["127.0.0.1", "localhost", "[::1]", "::1"].contains(base.host ?? "") else {
            throw SafetyError.insecureServer
        }
        let response = try await request("v1/auth/dev", method: "POST", body: .object(["email": .string(email)]))
        return try validateLogin(response)
    }
    #endif

    private func validateLogin(_ response: Data) throws -> LoginResponse {
        let login = try JSONDecoder().decode(LoginResponse.self, from: response)
        guard try MessageSafety.canonicalEmail(login.email) == login.email,
              !login.token.isEmpty, login.token.utf8.count <= 1024,
              login.token.utf8.allSatisfy({ (0x21...0x7e).contains($0) }),
              login.expires_at > Int64(Date().timeIntervalSince1970) else { throw SafetyError.invalidResponse }
        return login
    }

    func claim(email: String, token: String) async throws -> JSONValue {
        let response = try await request("v1/keys/claim", method: "POST", token: token, body: .object(["email": .string(email)]))
        let bundle = try JSONDecoder().decode(JSONValue.self, from: response)
        guard case .object(let fields) = bundle, fields["email"] == .string(email) else { throw SafetyError.invalidResponse }
        return bundle
    }

    func accountState(idToken: String, email: String) async throws -> AccountStateResponse? {
        let (data, response) = try await response("v1/account/state", method: "POST", body: .object(["id_token": .string(idToken)]))
        if response.statusCode == 404 {
            guard (try? JSONDecoder().decode([String: String].self, from: data)) == ["error": "not found"] else { throw SafetyError.invalidResponse }
            return nil
        }
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        guard response.statusCode == 200 else { throw SafetyError.network }
        return try JSONDecoder().decode(AccountStateResponse.self, from: data).validated(email: email)
    }

    func performAccountOperation(_ operation: AccountOperation, idToken: String) async throws {
        let (data, response) = try await response("v1/account/" + operation.kind.rawValue, method: "POST", body: operation.request(idToken: idToken))
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
        let data = try await request("v1/keys/maintenance", method: "GET", token: token)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    func maintainKeys(_ pending: JSONValue, token: String) async throws -> JSONValue {
        let data = try await request("v1/keys/maintenance", method: "PUT", token: token, body: pending)
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    func ownKeys(token: String) async throws -> JSONValue? {
        let (data, response) = try await response("v1/keys/me", method: "GET", token: token)
        if response.statusCode == 404 {
            guard (try? JSONDecoder().decode([String: String].self, from: data)) == ["error": "not found"] else { throw SafetyError.invalidResponse }
            return nil
        }
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        guard response.statusCode == 200 else { throw SafetyError.network }
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    func requireUnregisteredIdentity(token: String) async throws {
        let (data, response) = try await response("v1/keys/me", method: "GET", token: token)
        try AccountRegistration.requireUnregistered(statusCode: response.statusCode, body: data)
    }

    func upload(keys: JSONValue, token: String) async throws {
        _ = try await request("v1/keys", method: "PUT", token: token, body: keys)
    }

    func syncContacts(emails: [String], token: String) async throws {
        _ = try await request("v1/contacts", method: "PUT", token: token,
                              body: .object(["emails": .array(emails.map(JSONValue.string))]))
    }

    func send(_ envelope: SendRequest, token: String) async throws {
        _ = try await request("v1/messages", method: "POST", token: token, encodedBody: MessageTransport.paddedBody(envelope))
    }

    func trafficMode(token: String, allowLegacy: Bool) async throws -> TrafficModeResponse? {
        let (data, response) = try await response("v1/traffic-mode", method: "GET", token: token)
        if response.statusCode == 401 { throw SafetyError.unauthorized }
        if response.statusCode == 404 && allowLegacy { return nil }
        guard response.statusCode == 200 else { throw SafetyError.trafficUnavailable }
        return try JSONDecoder().decode(TrafficModeResponse.self, from: data).validated()
    }

    func setTrafficMode(cover: Bool, token: String) async throws -> TrafficModeResponse {
        let data = try await request("v1/traffic-mode", method: "PUT", token: token, body: .object(["cover": .bool(cover)]))
        let mode = try JSONDecoder().decode(TrafficModeResponse.self, from: data).validated()
        guard mode.cover == cover else { throw SafetyError.invalidResponse }
        return mode
    }

    func inbox(token: String) async throws -> [QueuedMessage] {
        struct Response: Decodable { let messages: [QueuedMessage] }
        let data = try await request("v1/messages?limit=\(Self.inboxPageSize)", method: "GET", token: token)
        let messages = try JSONDecoder().decode(Response.self, from: data).messages
        guard messages.count <= Self.inboxPageSize else { throw SafetyError.invalidResponse }
        return messages
    }

    func acknowledge(_ id: String, token: String) async throws {
        _ = try await request("v1/messages/ack", method: "POST", token: token, body: .object(["ids": .array([.string(id)])]))
    }

    func updatePushToken(_ deviceToken: String?, token: String) async throws {
        if let deviceToken {
            _ = try await request("v1/push-token", method: "PUT", token: token,
                                  body: .object(["token": .string(deviceToken)]))
        } else {
            _ = try await request("v1/push-token", method: "DELETE", token: token)
        }
    }

    private func request(_ path: String, method: String, token: String? = nil, body: JSONValue? = nil, encodedBody: Data? = nil) async throws -> Data {
        let (data, response) = try await response(path, method: method, token: token, body: body, encodedBody: encodedBody)
        if response.statusCode == 401 { throw SafetyError.unauthorized }
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
