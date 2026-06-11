// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ShadowSpace",
    platforms: [.macOS(.v14)],
    targets: [
        // 全原生代理核心（不依賴 sing-box；App Store 路線的基礎）
        .target(name: "ShadowCore", path: "Sources/ShadowCore"),
        .executableTarget(
            name: "shadow-demo",
            dependencies: ["ShadowCore"],
            path: "Sources/shadow-demo"
        ),
        .testTarget(
            name: "ShadowCoreTests",
            dependencies: ["ShadowCore"],
            path: "Tests/ShadowCoreTests"
        ),

        // 現有 GUI（仍走 sing-box 子程序；Developer ID 發佈路線）
        .target(name: "ShadowSpaceKit", dependencies: ["ShadowCore"], path: "Sources/ShadowSpaceKit"),
        .executableTarget(
            name: "ShadowSpace",
            dependencies: ["ShadowSpaceKit"],
            path: "Sources/ShadowSpace"
        ),
        .testTarget(
            name: "ShadowSpaceKitTests",
            dependencies: ["ShadowSpaceKit", "ShadowCore"],
            path: "Tests/ShadowSpaceKitTests"
        ),
    ]
)
