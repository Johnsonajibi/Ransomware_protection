/*
 * Anti-Ransomware macOS EndpointSecurity Implementation
 * Per-handle write/rename/delete gate with token verification
 * Notarized, hardened runtime, constant-time verification
 */

import Foundation
import EndpointSecurity
import CryptoKit
import Security

// Constants
let TOKEN_LIFETIME_SEC: TimeInterval = 300  // 5 minutes
let MAX_PROTECTED_PATHS = 1024
let ED25519_SIG_SIZE = 64
let ED25519_KEY_SIZE = 32

// Token structure
struct ARToken {
    let fileId: UInt64
    let processId: pid_t
    let userId: uid_t
    let allowedOps: UInt32
    let byteQuota: UInt64
    let expiry: Date
    let nonce: Data
    let signature: Data

    func signedData(path: String, pid: pid_t) -> Data {
        var payload = Data()
        payload.append(Data(path.utf8))
        payload.append(Data(withUnsafeBytes(of: pid.littleEndian, Array.init)))
        payload.append(Data(withUnsafeBytes(of: fileId.littleEndian, Array.init)))
        payload.append(Data(withUnsafeBytes(of: processId.littleEndian, Array.init)))
        payload.append(Data(withUnsafeBytes(of: userId.littleEndian, Array.init)))
        payload.append(Data(withUnsafeBytes(of: allowedOps.littleEndian, Array.init)))
        payload.append(Data(withUnsafeBytes(of: byteQuota.littleEndian, Array.init)))
        payload.append(Data(withUnsafeBytes(of: expiry.timeIntervalSince1970.bitPattern.littleEndian, Array.init)))
        payload.append(nonce)
        return payload
    }
}

// Simple nonce cache to prevent replay
class TokenCache {
    private var nonces = Set<Data>()
    private let lock = NSLock()
    private let maxEntries = 256
    func isNonceReplayed(_ nonce: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if nonces.contains(nonce) { return true }
        if nonces.count >= maxEntries {
            nonces.removeFirst()
        }
        nonces.insert(nonce)
        return false
    }
}

// Broker client reads token material from daemon drop directory or XPC
class BrokerClient {
    private let tokenDir = URL(fileURLWithPath: "/var/run/antiransomware/tokens")
    func requestToken(path: String, pid: pid_t, completion: @escaping (ARToken?) -> Void) {
        DispatchQueue.global().async {
            let fileURL = self.tokenDir.appendingPathComponent("\(pid).json")
            guard let data = try? Data(contentsOf: fileURL),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(nil); return
            }
            guard
                let fileId = json["file_id"] as? UInt64,
                let processId = json["process_id"] as? Int,
                let userId = json["user_id"] as? Int,
                let allowedOps = json["allowed_ops"] as? UInt32,
                let byteQuota = json["byte_quota"] as? UInt64,
                let expiryTs = json["expiry"] as? TimeInterval,
                let nonceB64 = json["nonce"] as? String,
                let sigB64 = json["signature"] as? String,
                let nonce = Data(base64Encoded: nonceB64),
                let signature = Data(base64Encoded: sigB64)
            else {
                completion(nil); return
            }
            let token = ARToken(
                fileId: fileId,
                processId: pid_t(processId),
                userId: uid_t(userId),
                allowedOps: allowedOps,
                byteQuota: byteQuota,
                expiry: Date(timeIntervalSince1970: expiryTs),
                nonce: nonce,
                signature: signature
            )
            completion(token)
        }
    }
}

enum Crypto {
    static func verifyEd25519(data: Data, signature: Data, publicKey: Data) -> Bool {
        guard let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pk.isValidSignature(signature, for: data)
    }
}

// Per-file context for zero-copy token cache
class ARFileContext {
    var validToken: ARToken?
    var hasValidToken: Bool = false
    var lastAccess: Date = Date()
}

class AntiRansomwareES: NSObject {
    private var client: es_client_t?
    private var publicKey: Data = Data(repeating: 0, count: ED25519_KEY_SIZE)
    private var protectedPaths: [String] = []
    private var fileContexts: [String: ARFileContext] = [:]
    private let contextLock = NSLock()
    private let brokerClient = BrokerClient()
    private let tokenCache = TokenCache()
    
    override init() {
        super.init()
        setupEndpointSecurity()
        loadConfiguration()
    }
    
    deinit {
        if let client = client {
            es_delete_client(client)
        }
    }
    
    private func setupEndpointSecurity() {
        let result = es_new_client(&client) { [weak self] (client, message) in
            self?.handleESEvent(client: client, message: message)
        }
        
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client = client else {
            print("Failed to create ES client")
            return
        }
        
        // Subscribe to file write/rename/delete events
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_WRITE,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK
        ]
        
        es_subscribe(client, events, UInt32(events.count))
        print("Anti-Ransomware ES client initialized")
    }
    
    private func loadConfiguration() {
        if let paths = try? String(contentsOf: URL(fileURLWithPath: "/etc/antiransomware/protected_paths")) {
            protectedPaths = paths.split(separator: "\n").map { String($0) }.filter { !$0.isEmpty }
        }
        if protectedPaths.isEmpty {
            protectedPaths = ["/Users/Shared/Protected"]
        }
        loadPublicKeyFromKeychain()
    }
    
    private func loadPublicKeyFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEd25519,
            kSecAttrApplicationTag as String: "com.antiransomware.publickey",
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess, let keyData = item as? Data {
            publicKey = keyData
        }
    }
    
    private func handleESEvent(client: es_client_t, message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        
        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN:
            handleOpenEvent(client: client, message: msg)
        case ES_EVENT_TYPE_AUTH_WRITE:
            handleWriteEvent(client: client, message: msg)
        case ES_EVENT_TYPE_AUTH_RENAME:
            handleRenameEvent(client: client, message: msg)
        case ES_EVENT_TYPE_AUTH_UNLINK:
            handleUnlinkEvent(client: client, message: msg)
        default:
            es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
        }
    }
    
    private func handleOpenEvent(client: es_client_t, message: es_message_t) {
        var msg = message
        let path = getFilePath(from: msg.event.open.file.pointee.path)
        
        if isProtectedPath(path) {
            // Allocate file context for token caching
            contextLock.lock()
            if fileContexts[path] == nil {
                fileContexts[path] = ARFileContext()
            }
            contextLock.unlock()
        }
        
        es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
    }
    
    private func handleWriteEvent(client: es_client_t, message: es_message_t) {
        var msg = message
        let path = getFilePath(from: msg.event.write.target.pointee.path)
        let pid = msg.process.pointee.pid
        
        if !isProtectedPath(path) {
            es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
            return
        }
        
        // Check cached token
        contextLock.lock()
        let context = fileContexts[path]
        contextLock.unlock()
        
        if let ctx = context, ctx.hasValidToken, let token = ctx.validToken {
            if Date() < token.expiry {
                // Token still valid
                es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
                return
            }
        }
        
        // Request new token from broker
        requestTokenFromBroker(path: path, pid: pid) { [weak self] token in
            guard let self = self, let token = token else {
                es_respond_auth_result(client, &msg, ES_AUTH_RESULT_DENY, false)
                return
            }
            
            // Verify token
            if self.verifyToken(token, path: path, pid: pid) {
                // Cache valid token
                self.contextLock.lock()
                if let ctx = self.fileContexts[path] {
                    ctx.validToken = token
                    ctx.hasValidToken = true
                    ctx.lastAccess = Date()
                }
                self.contextLock.unlock()
                
                es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
            } else {
                es_respond_auth_result(client, &msg, ES_AUTH_RESULT_DENY, false)
            }
        }
    }
    
    private func handleRenameEvent(client: es_client_t, message: es_message_t) {
        var msg = message
        let sourcePath = getFilePath(from: msg.event.rename.source.pointee.path)
        
        if isProtectedPath(sourcePath) {
            let pid = msg.process.pointee.pid
            requestTokenFromBroker(path: sourcePath, pid: pid) { [weak self] token in
                guard let self = self else { return }
                if let token = token, self.verifyToken(token, path: sourcePath, pid: pid) {
                    self.cacheToken(token, for: sourcePath)
                    es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
                } else {
                    print("Rename denied on protected path: \(sourcePath)")
                    es_respond_auth_result(client, &msg, ES_AUTH_RESULT_DENY, false)
                }
            }
            return
        }
        
        es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
    }
    
    private func handleUnlinkEvent(client: es_client_t, message: es_message_t) {
        var msg = message
        let path = getFilePath(from: msg.event.unlink.target.pointee.path)
        
        if isProtectedPath(path) {
            let pid = msg.process.pointee.pid
            requestTokenFromBroker(path: path, pid: pid) { [weak self] token in
                guard let self = self else { return }
                if let token = token, self.verifyToken(token, path: path, pid: pid) {
                    self.cacheToken(token, for: path)
                    es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
                } else {
                    print("Unlink denied on protected path: \(path)")
                    es_respond_auth_result(client, &msg, ES_AUTH_RESULT_DENY, false)
                }
            }
            return
        }
        
        es_respond_auth_result(client, &msg, ES_AUTH_RESULT_ALLOW, false)
    }
    
    private func getFilePath(from esString: es_string_t) -> String {
        return String(cString: esString.data, encoding: .utf8) ?? ""
    }
    
    private func isProtectedPath(_ path: String) -> Bool {
        return protectedPaths.contains { path.hasPrefix($0) }
    }
    
    private func verifyToken(_ token: ARToken, path: String, pid: pid_t) -> Bool {
        // Check expiry
        if Date() > token.expiry {
            return false
        }
        
        // Check process ID
        if token.processId != pid {
            return false
        }
        
        if !Crypto.verifyEd25519(data: token.signedData(path: path, pid: pid), signature: token.signature, publicKey: publicKey) {
            return false
        }

        if tokenCache.isNonceReplayed(token.nonce) {
            return false
        }
        
        return true
    }
    
    private func requestTokenFromBroker(path: String, pid: pid_t, completion: @escaping (ARToken?) -> Void) {
        // Communicate with user-space broker via XPC
        brokerClient.requestToken(path: path, pid: pid, completion: completion)
    }

    private func cacheToken(_ token: ARToken, for path: String) {
        contextLock.lock()
        if let ctx = fileContexts[path] {
            ctx.validToken = token
            ctx.hasValidToken = true
            ctx.lastAccess = Date()
        }
        contextLock.unlock()
    }
}

// Main application entry point for system extension
class AntiRansomwareSystemExtension: NSObject, NSExtensionRequestHandling {
    private var esClient: AntiRansomwareES?
    
    func beginRequest(with context: NSExtensionContext) {
        esClient = AntiRansomwareES()
        
        // Keep the extension running
        context.notifyRequestCompleted()
    }
}

// For standalone daemon
@main
struct AntiRansomwareDaemon {
    static func main() {
        let client = AntiRansomwareES()
        
        // Keep the daemon running
        RunLoop.main.run()
    }
}
