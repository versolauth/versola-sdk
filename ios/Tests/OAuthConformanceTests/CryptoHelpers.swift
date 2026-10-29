import CryptoKit
import Foundation

func import_CryptoKit_HMAC(key: Data, message: Data) -> [UInt8] {
    Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
}
