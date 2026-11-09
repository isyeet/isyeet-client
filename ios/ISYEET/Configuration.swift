import Foundation

struct Configuration {
    let server: URL
    let environment: ServiceEnvironment
    let passkeyRelyingParty: String
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
        guard let relyingParty = bundle.object(forInfoDictionaryKey: "ISYEETPasskeyRelyingParty") as? String,
              relyingParty == server.host, ["api.isyeet.io", "api-staging.isyeet.io"].contains(relyingParty) else {
            throw SafetyError.configuration
        }
        passkeyRelyingParty = relyingParty
    }
}
