// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ISYEETDomain",
    platforms: [.macOS(.v13)],
    products: [.library(name: "ISYEETDomain", targets: ["ISYEETDomain"])],
    targets: [.target(name: "ISYEETDomain"), .testTarget(name: "ISYEETDomainTests", dependencies: ["ISYEETDomain"])]
)
