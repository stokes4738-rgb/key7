import Foundation
import CryptoKit
import LocalAuthentication
import Security

// FIDO2/CTAP2.0 ES256, non-discoverable credentials only.
// SECURITY NOTE: Research prototype. Do not enroll real accounts.
final class Authenticator {
    let vault = CredentialVault()
    private let aaguid = Data(repeating: 0, count: 16) // no vendor attestation

    static func error(_ code: UInt8) -> Data { Data([code]) }
    private func success(_ cbor: CBOR) -> Data { Data([0]) + cbor.encoded() }

    func process(_ request: Data, needsApproval: @escaping (String, @escaping (Bool) -> Void) -> Void,
                 completion: @escaping (Data) -> Void) {
        guard let command = request.first else { completion(Self.error(0x03)); return }
        switch command {
        case 0x04: // authenticatorGetInfo
            guard request.count == 1 else { completion(Self.error(0x03)); return }
            let ctx = LAContext()
            let canVerify = ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
            completion(success(.map([
                (.unsigned(1), .array([.text("FIDO_2_0")])),
                (.unsigned(3), .bytes(aaguid)),
                (.unsigned(4), .map([
                    (.text("plat"), .bool(false)),
                    (.text("rk"), .bool(false)),
                    (.text("up"), .bool(true)),
                    (.text("uv"), .bool(canVerify))
                ])),
                (.unsigned(5), .unsigned(4096)),
                (.unsigned(7), .unsigned(16)),
                (.unsigned(8), .unsigned(32)),
                (.unsigned(9), .array([.text("ble")])),
                (.unsigned(10), .array([.map([(.text("alg"), .negative(-7)), (.text("type"), .text("public-key"))])]))
            ])))
        case 0x01: create(request.dropFirst(), needsApproval: needsApproval, completion: completion)
        case 0x02: assert(request.dropFirst(), needsApproval: needsApproval, completion: completion)
        default: completion(Self.error(0x01)) // CTAP1_ERR_INVALID_COMMAND
        }
    }

    private func create(_ data: Data.SubSequence,
                        needsApproval: @escaping (String, @escaping (Bool) -> Void) -> Void,
                        completion: @escaping (Data) -> Void) {
        guard let args = CBOR.decode(Data(data)),
              let hash = args[1]?.data, hash.count == 32,
              let rpID = args[2]?["id"]?.string, !rpID.isEmpty, rpID.utf8.count <= 253,
              let userID = args[3]?["id"]?.data, !userID.isEmpty,
              let params = args[4]?.arrayItems else {
            completion(Self.error(0x12)); return // INVALID_CBOR / invalid params
        }
        let acceptsES256 = params.contains { $0["type"]?.string == "public-key" && $0["alg"]?.intValue == -7 }
        guard acceptsES256 else { completion(Self.error(0x26)); return } // UNSUPPORTED_ALGORITHM
        if args[7]?["rk"]?.boolValue == true { completion(Self.error(0x2B)); return }
        if args[8] != nil { completion(Self.error(0x2B)); return } // PIN/UV protocol not implemented
        if let excluded = args[5]?.arrayItems {
            do {
                for item in excluded {
                    if let id = item["id"]?.data, try vault.find(rpID: rpID, id: id) != nil {
                        completion(Self.error(0x19)); return // CREDENTIAL_EXCLUDED
                    }
                }
            } catch { completion(Self.error(0x7F)); return }
        }
        needsApproval("Create a security-key credential for \(rpID)?") { approved in
            guard approved else { completion(Self.error(0x27)); return }
            do {
                let privateKey = P256.Signing.PrivateKey()
                var identifier = Data(count: 32)
                let entropyStatus = identifier.withUnsafeMutableBytes { buffer -> Int32 in
                    guard let base = buffer.baseAddress else { return -1 }
                    return SecRandomCopyBytes(kSecRandomDefault, 32, base)
                }
                guard entropyStatus == errSecSuccess else { completion(Self.error(0x7F)); return }
                let stored = StoredCredential(rpID: rpID, credentialID: identifier, userID: userID,
                                              privateKey: privateKey.rawRepresentation, signatureCount: 0)
                try self.vault.insert(stored)
                let publicBytes = privateKey.publicKey.x963Representation
                guard publicBytes.count == 65, publicBytes.first == 0x04 else {
                    completion(Self.error(0x7F)); return
                }
                let cose = CBOR.map([
                    (.unsigned(1), .unsigned(2)), // EC2 key type
                    (.unsigned(3), .negative(-7)), // ES256
                    (.negative(-1), .unsigned(1)), // P-256 curve
                    (.negative(-2), .bytes(Data(publicBytes[1..<33]))),
                    (.negative(-3), .bytes(Data(publicBytes[33..<65])))
                ]).encoded()
                var authData = Data(SHA256.hash(data: Data(rpID.utf8)))
                authData.append(0x45) // UP | UV | AT
                authData.append(contentsOf: [0, 0, 0, 0]) // signature counter
                authData.append(self.aaguid)
                authData.append(contentsOf: [0, UInt8(identifier.count)])
                authData.append(identifier)
                authData.append(cose)
                let response: CBOR = .map([
                    (.unsigned(1), .text("none")),
                    (.unsigned(2), .bytes(authData)),
                    (.unsigned(3), .map([]))
                ])
                completion(self.success(response))
                _ = hash // required input, used in signed attestation formats; none attestation does not sign it
            } catch { completion(Self.error(0x7F)) }
        }
    }

    private func assert(_ data: Data.SubSequence,
                        needsApproval: @escaping (String, @escaping (Bool) -> Void) -> Void,
                        completion: @escaping (Data) -> Void) {
        guard let args = CBOR.decode(Data(data)),
              let rpID = args[1]?.string, !rpID.isEmpty,
              let clientHash = args[2]?.data, clientHash.count == 32 else {
            completion(Self.error(0x12)); return
        }
        if args[6] != nil { completion(Self.error(0x2B)); return } // PIN/UV protocol not implemented
        // No resident/discoverable credentials: caller must supply an allowList.
        guard let candidates = args[3]?.arrayItems, !candidates.isEmpty else {
            completion(Self.error(0x2E)); return
        }
        let match: StoredCredential?
        do {
            let all = try vault.all()
            match = candidates.compactMap { $0["id"]?.data }.compactMap { id in
                all.first(where: { $0.rpID == rpID && $0.credentialID == id })
            }.first
        } catch { completion(Self.error(0x7F)); return }
        guard let credential = match else { completion(Self.error(0x2E)); return }
        needsApproval("Sign in to \(rpID) with your security key?") { approved in
            guard approved else { completion(Self.error(0x27)); return }
            do {
                let updated = try self.vault.bumpCounter(rpID: rpID, id: credential.credentialID)
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: updated.privateKey)
                var authData = Data(SHA256.hash(data: Data(rpID.utf8)))
                authData.append(0x05) // UP | UV, no AT
                let count = updated.signatureCount
                authData.append(contentsOf: [UInt8((count >> 24) & 0xFF), UInt8((count >> 16) & 0xFF),
                                             UInt8((count >> 8) & 0xFF), UInt8(count & 0xFF)])
                let signature = try privateKey.signature(for: authData + clientHash)
                let response: CBOR = .map([
                    (.unsigned(1), .map([(.text("type"), .text("public-key")),
                                        (.text("id"), .bytes(updated.credentialID))])),
                    (.unsigned(2), .bytes(authData)),
                    (.unsigned(3), .bytes(signature.derRepresentation)),
                    (.unsigned(4), .map([(.text("id"), .bytes(updated.userID))]))
                ])
                completion(self.success(response))
            } catch { completion(Self.error(0x7F)) }
        }
    }
}
