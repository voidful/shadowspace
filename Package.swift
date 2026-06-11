// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ShadowSpace",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "ShadowSpaceKit", path: "Sources/ShadowSpaceKit"),
        .executableTarget(
            name: "ShadowSpace",
            dependencies: ["ShadowSpaceKit"],
            path: "Sources/ShadowSpace"
        ),
        .testTarget(
            name: "ShadowSpaceKitTests",
            dependencies: ["ShadowSpaceKit"],
            path: "Tests/ShadowSpaceKitTests"
        ),
    ]
)
