import XCTest
@testable import OAuthCore

final class Base64UrlTests: XCTestCase {
    func testEncodeUsesUrlSafeAlphabetWithoutPadding() {
        // 0xFB 0xFF encodes to "+/8=" in the standard alphabet.
        XCTAssertEqual(Base64Url.encode(Data([0xFB, 0xFF])), "-_8")
        XCTAssertEqual(Base64Url.encode(Data([0x66])), "Zg")
        XCTAssertEqual(Base64Url.encode(Data()), "")
    }

    func testDecodeAcceptsUnpaddedAndPaddedInput() {
        XCTAssertEqual(Base64Url.decode("Zg"), Data([0x66]))
        XCTAssertEqual(Base64Url.decode("Zg=="), Data([0x66]))
        XCTAssertEqual(Base64Url.decode("-_8"), Data([0xFB, 0xFF]))
        XCTAssertEqual(Base64Url.decode(""), Data())
    }

    func testDecodeRefusesTheStandardAlphabetAndStrayCharacters() {
        XCTAssertNil(Base64Url.decode("+/8="))
        XCTAssertNil(Base64Url.decode("Zg=g"))
        XCTAssertNil(Base64Url.decode("Z g"))
        XCTAssertNil(Base64Url.decode("Zg\n"))
    }

    func testDecodeRefusesALengthNoByteSequenceProduces() {
        XCTAssertNil(Base64Url.decode("A"))
        XCTAssertNil(Base64Url.decode("ABCDE"))
    }

    func testRoundTripOverEveryLengthAndByteValue() {
        for length in 0..<40 {
            let data = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) })
            XCTAssertEqual(Base64Url.decode(Base64Url.encode(data)), data, "length \(length)")
        }
        let all = Data(0...255)
        XCTAssertEqual(Base64Url.decode(Base64Url.encode(all)), all)
    }
}
