import AuthenticationServices
import Foundation
import UIKit

@MainActor
final class Passkeys: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private var controller: ASAuthorizationController?
    private var continuation: CheckedContinuation<JSONValue, Error>?

    func credential(_ challenge: PasskeyChallenge, configuration: Configuration, registering: Bool,
                    securityKey: Bool = false, excludingCredentialID: String? = nil) async throws -> JSONValue {
        let options = challenge.public_key
        guard continuation == nil,
              let bytes = Data(base64URL: options.challenge), (16...128).contains(bytes.count),
              (options.rp?.id ?? options.rpId) == configuration.passkeyRelyingParty else { throw SafetyError.invalidResponse }
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: configuration.passkeyRelyingParty)
        let hardware = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: configuration.passkeyRelyingParty)
        let requests: [ASAuthorizationRequest]
        if registering {
            guard let user = options.user, let userID = Data(base64URL: user.id), (1...64).contains(userID.count),
                  let username = challenge.username, try MessageSafety.canonicalUsername(username) == username,
                  user.name == username, options.pubKeyCredParams?.contains(where: { $0.type == "public-key" && $0.alg == -7 }) == true else {
                throw SafetyError.invalidResponse
            }
            let excluded = try descriptorIDs(options.excludeCredentials ?? [])
            if securityKey {
                let request = hardware.createCredentialRegistrationRequest(challenge: bytes, displayName: "@" + username, name: username, userID: userID)
                request.userVerificationPreference = .required
                request.residentKeyPreference = .required
                request.attestationPreference = .none
                request.credentialParameters = [ASAuthorizationPublicKeyCredentialParameters(algorithm: ASCOSEAlgorithmIdentifier(rawValue: -7))]
                request.excludedCredentials = excluded.map { ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: $0, transports: [.usb, .nfc, .bluetooth]) }
                requests = [request]
            } else {
                let request = provider.createCredentialRegistrationRequest(challenge: bytes, name: username, userID: userID)
                request.displayName = "@" + username
                request.userVerificationPreference = .required
                request.attestationPreference = .none
                if #available(iOS 17.4, *) {
                    request.excludedCredentials = excluded.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
                } else if !excluded.isEmpty {
                    // iOS 17.0 cannot enforce native platform credential exclusion.
                    // Never risk overwriting the credential needed to authorize this change.
                    throw SafetyError.passkeyUnavailable
                }
                requests = [request]
            }
        } else {
            let descriptors = (options.allowCredentials ?? []).filter { $0.id != excludingCredentialID }
            guard excludingCredentialID == nil || !descriptors.isEmpty else { throw SafetyError.passkeyUnavailable }
            let allowed = try descriptorIDs(descriptors)
            let request = provider.createCredentialAssertionRequest(challenge: bytes)
            request.userVerificationPreference = .required
            request.allowedCredentials = allowed.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
            let securityRequest = hardware.createCredentialAssertionRequest(challenge: bytes)
            securityRequest.userVerificationPreference = .required
            securityRequest.allowedCredentials = allowed.map { ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: $0, transports: [.usb, .nfc, .bluetooth]) }
            requests = [request, securityRequest]
        }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: requests)
            self.controller = controller
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    private func descriptorIDs(_ values: [PasskeyOptions.Descriptor]) throws -> [Data] {
        guard values.count <= 8 else { throw SafetyError.invalidResponse }
        return try values.map {
            guard $0.type == "public-key", let id = Data(base64URL: $0.id), id.count <= 1024 else { throw SafetyError.invalidResponse }
            return id
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        do {
            let id: Data
            let response: [String: JSONValue]
            if let credential = authorization.credential as? any ASAuthorizationPublicKeyCredentialRegistration {
                guard let attestation = credential.rawAttestationObject else { throw SafetyError.invalidResponse }
                id = credential.credentialID
                response = ["clientDataJSON": .string(credential.rawClientDataJSON.base64URL), "attestationObject": .string(attestation.base64URL)]
            } else if let credential = authorization.credential as? any ASAuthorizationPublicKeyCredentialAssertion {
                guard let authenticatorData = credential.rawAuthenticatorData, let signature = credential.signature,
                      !authenticatorData.isEmpty, !signature.isEmpty else { throw SafetyError.invalidResponse }
                let userHandle = credential.userID.flatMap { $0.isEmpty ? nil : JSONValue.string($0.base64URL) } ?? .null
                id = credential.credentialID
                response = ["clientDataJSON": .string(credential.rawClientDataJSON.base64URL),
                            "authenticatorData": .string(authenticatorData.base64URL),
                            "signature": .string(signature.base64URL), "userHandle": userHandle]
            } else { throw SafetyError.invalidResponse }
            finish(.success(.object(["id": .string(id.base64URL), "rawId": .string(id.base64URL),
                                     "type": .string("public-key"), "response": .object(response), "clientExtensionResults": .object([:])])))
        } catch { finish(.failure(error)) }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        if (error as? ASAuthorizationError)?.code == .canceled { finish(.failure(CancellationError())) }
        else { finish(.failure(SafetyError.passkeyUnavailable)) }
    }

    private func finish(_ result: Result<JSONValue, Error>) {
        let pending = continuation
        continuation = nil
        controller = nil
        pending?.resume(with: result)
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows).first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }
}
