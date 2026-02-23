// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0"),
        .package(url: "https://github.com/vapor/vapor", from: "4.89.0"),
    ],
    targets: [
        .target(name: "MyApp", dependencies: [
            .product(name: "NIO", package: "swift-nio"),
            .product(name: "Vapor", package: "vapor"),
        ]),
    ]
)
