// swift-tools-version:5.9
import PackageDescription

// .package(url: "https://github.com/old/dep", from: "1.0.0")
/* .package(url: "https://github.com/removed/dep", from: "2.0.0") */

let package = Package(
    name: "CommentedApp",
    dependencies: [
        .package(url: "https://github.com/real/dep", from: "3.0.0"),
    ],
    targets: []
)
