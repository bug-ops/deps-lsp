// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ComplexApp",
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0"),
        .package(url: "https://github.com/apple/swift-log", .upToNextMajor(from: "1.5.0")),
        .package(url: "https://github.com/apple/swift-metrics", .upToNextMinor(from: "2.3.0")),
        .package(url: "https://github.com/apple/swift-crypto", .exact("3.0.0")),
        .package(url: "https://github.com/foo/bar", "1.0.0"..<"2.0.0"),
        .package(url: "https://github.com/baz/qux", "1.0.0"..."1.9.9"),
        .package(url: "https://github.com/dev/tool", .branch("main")),
        .package(url: "https://github.com/dev/debug", .revision("abc123")),
        .package(path: "../LocalPackage"),
    ],
    targets: []
)
