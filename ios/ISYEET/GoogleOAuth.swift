import AuthenticationServices
import CryptoKit
import Foundation
import Security
import UIKit

struct GoogleCredential {
    let idToken: String
    let email: String
}

@MainActor
final class GoogleOAuth: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?
    private var continuation: CheckedContinuation<URL, Error>?

    func idToken(configuration: Configuration) async throws -> GoogleCredential {
        let verifier = try randomString()
        let state = try randomString()
        let nonce = try randomString()
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URL
        var components = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: configuration.googleClientID),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: "openid email"),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "prompt", value: "select_account"),
        ]
        guard let authURL = components.url else { throw SafetyError.configuration }
        let callback = try await browser(url: authURL, callbackScheme: configuration.callbackScheme)
        guard let result = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              result.scheme == configuration.callbackScheme, result.host == nil,
              result.path == "/oauthredirect", result.fragment == nil else { throw SafetyError.invalidResponse }
        let parameters = Dictionary(grouping: result.queryItems ?? [], by: \.name)
        guard parameters["state"]?.count == 1, let returnedState = parameters["state"]?.first?.value,
              constantTimeEqual(state, returnedState), parameters["error"] == nil,
              parameters["code"]?.count == 1, let code = parameters["code"]?.first?.value, !code.isEmpty else {
            throw SafetyError.invalidResponse
        }

        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let fields = ["client_id": configuration.googleClientID, "redirect_uri": configuration.redirectURI,
                      "code": code, "code_verifier": verifier, "grant_type": "authorization_code"]
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        request.httpBody = Data(fields.sorted(by: { $0.key < $1.key }).map {
            $0.key + "=" + $0.value.addingPercentEncoding(withAllowedCharacters: allowed)!
        }.joined(separator: "&").utf8)
        let (data, response) = try await Network.boundedData(for: request)
        guard response.statusCode == 200 else { throw SafetyError.unauthorized }
        struct TokenResponse: Decodable { let id_token: String }
        let token = try JSONDecoder().decode(TokenResponse.self, from: data).id_token
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, token.utf8.count < 16384,
              let payload = Data(base64URL: String(parts[1])) else { throw SafetyError.invalidResponse }
        struct Claims: Decodable {
            let nonce: String
            let aud: String
            let exp: Int64
            let iss: String
            let email: String
            let email_verified: Bool
            let hd: String?
        }
        let claims = try JSONDecoder().decode(Claims.self, from: payload)
        // The backend verifies the JWT signature, issuer, audience and account
        // claims. Bind that signed token to this browser transaction here.
        guard constantTimeEqual(nonce, claims.nonce), claims.aud == configuration.googleClientID,
              claims.exp > Int64(Date().timeIntervalSince1970),
              ["accounts.google.com", "https://accounts.google.com"].contains(claims.iss) else { throw SafetyError.invalidResponse }
        let email = try MessageSafety.googleAccountEmail(claims.email, emailVerified: claims.email_verified, hostedDomain: claims.hd)
        return GoogleCredential(idToken: token, email: email)
    }

    private func browser(url: URL, callbackScheme: String) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let session = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { [weak self] url, error in
                Task { @MainActor in
                    guard let self, let continuation = self.continuation else { return }
                    self.continuation = nil
                    self.session = nil
                    if let url { continuation.resume(returning: url) }
                    else { continuation.resume(throwing: error ?? SafetyError.unauthorized) }
                }
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            self.session = session
            if !session.start() {
                self.continuation = nil
                self.session = nil
                continuation.resume(throwing: SafetyError.unauthorized)
            }
        }
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows).first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }

    private func randomString() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw SafetyError.invalidResponse }
        return Data(bytes).base64URL
    }

    private func constantTimeEqual(_ first: String, _ second: String) -> Bool {
        let a = Array(first.utf8), b = Array(second.utf8)
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}

private extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    init?(base64URL: String) {
        var value = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        self.init(base64Encoded: value)
    }
}
