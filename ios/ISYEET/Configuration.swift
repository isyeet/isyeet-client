import Foundation

struct Configuration {
    let server: URL
    let environment: ServiceEnvironment
    let googleClientID: String
    let callbackScheme: String
    private(set) var simulatorDevelopmentEmail: String?
    var redirectURI: String { callbackScheme + ":/oauthredirect" }

    init(bundle: Bundle = .main) throws {
        guard let serverString = bundle.object(forInfoDictionaryKey: "ISYEETServerURL") as? String else { throw SafetyError.configuration }
        #if DEBUG
        let allowLocal = (bundle.object(forInfoDictionaryKey: "ISYEETAllowLoopbackHTTP") as? String) == "YES"
        #else
        let allowLocal = false
        #endif
        server = try MessageSafety.serverURL(serverString, allowLoopbackHTTP: allowLocal)
        guard let environmentName = bundle.object(forInfoDictionaryKey: "ISYEETEnvironment") as? String else { throw SafetyError.configuration }
        environment = try ServiceEnvironment(name: environmentName, server: server, allowLocal: allowLocal)
        #if DEBUG && targetEnvironment(simulator)
        if let email = ProcessInfo.processInfo.environment["ISYEET_SIMULATOR_DEV_EMAIL"], allowLocal {
            guard server.scheme == "http", ["127.0.0.1", "localhost", "[::1]", "::1"].contains(server.host ?? "") else {
                throw SafetyError.insecureServer
            }
            simulatorDevelopmentEmail = try MessageSafety.canonicalEmail(email)
            googleClientID = ""
            callbackScheme = ""
            return
        }
        #endif
        guard let clientID = bundle.object(forInfoDictionaryKey: "ISYEETGoogleClientID") as? String,
              clientID.hasSuffix(".apps.googleusercontent.com"), !clientID.contains("REPLACE"),
              let scheme = bundle.object(forInfoDictionaryKey: "ISYEETCallbackScheme") as? String,
              scheme == clientID.split(separator: ".").reversed().joined(separator: ".") else { throw SafetyError.configuration }
        googleClientID = clientID
        callbackScheme = scheme
    }
}
