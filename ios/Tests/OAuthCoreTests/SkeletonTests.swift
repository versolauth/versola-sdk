import XCTest
@testable import OAuthCore

final class SkeletonTests: XCTestCase {
    func testMetadataDecodesSnakeCaseAndDefaultsMissingMembers() throws {
        let json = #"{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/authorize","token_endpoint":"https://id.example.com/token","unknown":1}"#
        let metadata = try JSONDecoder().decode(ProviderMetadata.self, from: Data(json.utf8))
        XCTAssertEqual(metadata.issuer, "https://id.example.com")
        XCTAssertFalse(metadata.supportsDpop)
        XCTAssertNoThrow(try metadata.validate(configuredIssuer: "https://id.example.com/"))
    }
}
