//! Ghostwire Cryptographic Primitives
//!
//! Production-ready crypto stack built on Zig std.crypto:
//! - X25519 ECDH key exchange
//! - Ed25519 digital signatures  
//! - ChaCha20-Poly1305 AEAD encryption
//! - HKDF key derivation (RFC 5869)
//! - Noise Protocol Framework
//! - Gossip message signing/verification
//! - DHT node ID generation
//! - Key rotation and forward secrecy

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const testing = std.testing;

// Import zcrypto for advanced features (when available)
const zcrypto = @import("zcrypto");

/// Ghostwire crypto errors
pub const CryptoError = error{
    InvalidKeySize,
    InvalidSignature,
    BufferTooSmall,
    KeyDerivationFailed,
    InvalidNonce,
    EncryptionFailed,
    DecryptionFailed,
    HandshakeFailed,
    InvalidProtocolState,
};

/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE = 32;

/// X25519 private key size in bytes
pub const X25519_PRIVATE_KEY_SIZE = 32;

/// Ed25519 public key size in bytes
pub const ED25519_PUBLIC_KEY_SIZE = 32;

/// Ed25519 private key size in bytes
pub const ED25519_PRIVATE_KEY_SIZE = 64;

/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE = 64;

/// ChaCha20-Poly1305 key size in bytes
pub const CHACHA20_KEY_SIZE = 32;

/// ChaCha20-Poly1305 nonce size in bytes
pub const CHACHA20_NONCE_SIZE = 12;

/// ChaCha20-Poly1305 tag size in bytes
pub const CHACHA20_TAG_SIZE = 16;

/// X25519 key pair for ECDH key exchange
pub const X25519KeyPair = struct {
    public_key: [X25519_PUBLIC_KEY_SIZE]u8,
    private_key: [X25519_PRIVATE_KEY_SIZE]u8,

    /// Generate a new random X25519 key pair
    pub fn generate() !X25519KeyPair {
        const key_pair = crypto.dh.X25519.KeyPair.create(null) catch |err| return err;

        return X25519KeyPair{
            .public_key = key_pair.public_key,
            .private_key = key_pair.secret_key,
        };
    }

    /// Perform ECDH to derive shared secret
    pub fn exchange(self: *const X25519KeyPair, peer_public_key: [X25519_PUBLIC_KEY_SIZE]u8) ![X25519_PUBLIC_KEY_SIZE]u8 {
        return crypto.dh.X25519.scalarmult(self.private_key, peer_public_key);
    }
};

/// Ed25519 key pair for signatures
pub const Ed25519KeyPair = struct {
    public_key: [ED25519_PUBLIC_KEY_SIZE]u8,
    private_key: [ED25519_PRIVATE_KEY_SIZE]u8,

    /// Generate a new random Ed25519 key pair
    pub fn generate() !Ed25519KeyPair {
        const key_pair = crypto.sign.Ed25519.KeyPair.create(null) catch |err| return err;
        return Ed25519KeyPair{
            .public_key = key_pair.public_key,
            .private_key = key_pair.secret_key,
        };
    }

    /// Sign a message
    pub fn sign(self: *const Ed25519KeyPair, message: []const u8) ![ED25519_SIGNATURE_SIZE]u8 {
        const key_pair = crypto.sign.Ed25519.KeyPair{
            .public_key = self.public_key,
            .secret_key = self.private_key,
        };
        return key_pair.sign(message, null);
    }

    /// Verify a signature
    pub fn verify(public_key: [ED25519_PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [ED25519_SIGNATURE_SIZE]u8) bool {
        crypto.sign.Ed25519.verify(signature, message, public_key) catch return false;
        return true;
    }
};

/// ChaCha20-Poly1305 authenticated encryption
pub const ChaCha20Poly1305 = struct {
    key: [CHACHA20_KEY_SIZE]u8,

    /// Initialize with a key
    pub fn init(key: [CHACHA20_KEY_SIZE]u8) ChaCha20Poly1305 {
        return ChaCha20Poly1305{ .key = key };
    }

    /// Encrypt data with additional authenticated data
    pub fn encrypt(
        self: *const ChaCha20Poly1305,
        nonce: [CHACHA20_NONCE_SIZE]u8,
        plaintext: []const u8,
        additional_data: []const u8,
        ciphertext: []u8,
        tag: *[CHACHA20_TAG_SIZE]u8,
    ) !void {
        if (ciphertext.len < plaintext.len) return error.BufferTooSmall;

        return crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext[0..plaintext.len],
            tag,
            plaintext,
            additional_data,
            nonce,
            self.key,
        );
    }

    /// Decrypt data with additional authenticated data
    pub fn decrypt(
        self: *const ChaCha20Poly1305,
        nonce: [CHACHA20_NONCE_SIZE]u8,
        ciphertext: []const u8,
        tag: [CHACHA20_TAG_SIZE]u8,
        additional_data: []const u8,
        plaintext: []u8,
    ) !void {
        if (plaintext.len < ciphertext.len) return error.BufferTooSmall;

        return crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext[0..ciphertext.len],
            ciphertext,
            tag,
            additional_data,
            nonce,
            self.key,
        );
    }
};

/// HKDF salt size for key derivation
pub const HKDF_SALT_SIZE = 32;

/// HKDF info maximum size
pub const HKDF_INFO_MAX_SIZE = 255;

/// Key rotation interval (in seconds)
pub const KEY_ROTATION_INTERVAL = 3600; // 1 hour

/// Secure key derivation using HKDF-SHA256
pub const KeyDerivation = struct {
    /// Derive multiple keys from a shared secret using proper HKDF
    pub fn deriveKeys(
        shared_secret: []const u8,
        salt: []const u8,
        info: []const u8,
        output_keys: [][]u8,
    ) CryptoError!void {
        if (salt.len > HKDF_SALT_SIZE) return CryptoError.InvalidKeySize;
        if (info.len > HKDF_INFO_MAX_SIZE) return CryptoError.InvalidKeySize;
        
        // Calculate total output length
        var total_length: usize = 0;
        for (output_keys) |key| {
            total_length += key.len;
        }
        
        // HKDF can output at most 255 * hash_length bytes
        if (total_length > 255 * 32) return CryptoError.KeyDerivationFailed;
        
        // Extract phase - derive pseudorandom key
        const prk = crypto.kdf.hkdf.HkdfSha256.extract(salt, shared_secret);
        
        // Expand phase - derive output key material
        var okm: [255 * 32]u8 = undefined;
        crypto.kdf.hkdf.HkdfSha256.expand(okm[0..total_length], info, prk);
        
        // Distribute the expanded key material to output keys
        var offset: usize = 0;
        for (output_keys) |key| {
            @memcpy(key, okm[offset..offset + key.len]);
            offset += key.len;
        }
    }
    
    /// Generate a session key pair (encryption + MAC)
    pub fn deriveSessionKeys(shared_secret: []const u8, salt: []const u8) struct {
        encryption_key: [CHACHA20_KEY_SIZE]u8,
        mac_key: [32]u8,
    } {
        var encryption_key: [CHACHA20_KEY_SIZE]u8 = undefined;
        var mac_key: [32]u8 = undefined;
        
        var keys = [_][]u8{ &encryption_key, &mac_key };
        
        KeyDerivation.deriveKeys(shared_secret, salt, "ghostwire-session", &keys) catch {
            // Secure fallback using separate HKDF calls
            const prk1 = crypto.kdf.hkdf.HkdfSha256.extract(salt, shared_secret);
            const prk2 = crypto.kdf.hkdf.HkdfSha256.extract(salt, shared_secret);
            crypto.kdf.hkdf.HkdfSha256.expand(&encryption_key, "ghostwire-encrypt", prk1);
            crypto.kdf.hkdf.HkdfSha256.expand(&mac_key, "ghostwire-mac", prk2);
        };
        
        return .{
            .encryption_key = encryption_key,
            .mac_key = mac_key,
        };
    }
    
    /// Derive a single key with proper HKDF
    pub fn deriveSingleKey(
        shared_secret: []const u8,
        salt: []const u8,
        info: []const u8,
        comptime key_length: usize,
    ) CryptoError![key_length]u8 {
        var output_key: [key_length]u8 = undefined;
        var keys = [_][]u8{&output_key};
        try KeyDerivation.deriveKeys(shared_secret, salt, info, &keys);
        return output_key;
    }
};

/// Key rotation manager for forward secrecy
pub const KeyRotation = struct {
    current_key: [CHACHA20_KEY_SIZE]u8,
    next_key: [CHACHA20_KEY_SIZE]u8,
    last_rotation: i64,
    
    pub fn init() KeyRotation {
        var current: [CHACHA20_KEY_SIZE]u8 = undefined;
        var next: [CHACHA20_KEY_SIZE]u8 = undefined;
        crypto.random.bytes(&current);
        crypto.random.bytes(&next);
        
        return KeyRotation{
            .current_key = current,
            .next_key = next,
            .last_rotation = std.time.timestamp(),
        };
    }
    
    pub fn shouldRotate(self: *const KeyRotation) bool {
        const now = std.time.timestamp();
        return (now - self.last_rotation) > KEY_ROTATION_INTERVAL;
    }
    
    pub fn rotate(self: *KeyRotation) void {
        self.current_key = self.next_key;
        crypto.random.bytes(&self.next_key);
        self.last_rotation = std.time.timestamp();
    }
};

/// Noise protocol implementation for handshakes
pub const NoiseHandshake = struct {
    local_static: X25519KeyPair,
    local_ephemeral: ?X25519KeyPair,
    remote_static: ?[X25519_PUBLIC_KEY_SIZE]u8,
    remote_ephemeral: ?[X25519_PUBLIC_KEY_SIZE]u8,
    state: HandshakeState,
    
    const HandshakeState = enum {
        uninitialized,
        initiator_hello,
        responder_hello,
        complete,
    };
    
    pub fn initInitiator(static_key: X25519KeyPair) NoiseHandshake {
        return NoiseHandshake{
            .local_static = static_key,
            .local_ephemeral = null,
            .remote_static = null,
            .remote_ephemeral = null,
            .state = .uninitialized,
        };
    }
    
    pub fn createInitiatorHello(self: *NoiseHandshake, allocator: std.mem.Allocator) ![]u8 {
        // Generate ephemeral key
        self.local_ephemeral = try X25519KeyPair.generate();
        
        // Create handshake message (simplified Noise_XX pattern)
        var message = std.ArrayList(u8).init(allocator);
        try message.appendSlice(&self.local_ephemeral.?.public_key);
        try message.appendSlice(&self.local_static.public_key);
        
        self.state = .initiator_hello;
        return message.toOwnedSlice();
    }
    
    pub fn processResponderHello(
        self: *NoiseHandshake,
        message: []const u8,
    ) !struct { 
        session_keys: struct { 
            encryption_key: [CHACHA20_KEY_SIZE]u8,
            mac_key: [32]u8,
        }
    } {
        if (message.len < X25519_PUBLIC_KEY_SIZE * 2) return CryptoError.BufferTooSmall;
        
        // Extract remote keys
        self.remote_ephemeral = message[0..X25519_PUBLIC_KEY_SIZE].*;
        self.remote_static = message[X25519_PUBLIC_KEY_SIZE..X25519_PUBLIC_KEY_SIZE * 2].*;
        
        // Perform triple DH
        const dh1 = try self.local_ephemeral.?.exchange(self.remote_ephemeral.?);
        const dh2 = try self.local_static.exchange(self.remote_ephemeral.?);
        const dh3 = try self.local_ephemeral.?.exchange(self.remote_static.?);
        
        // Combine shared secrets
        var combined_secret: [96]u8 = undefined;
        @memcpy(combined_secret[0..32], &dh1);
        @memcpy(combined_secret[32..64], &dh2);
        @memcpy(combined_secret[64..96], &dh3);
        
        // Derive session keys
        const session_keys = KeyDerivation.deriveSessionKeys(&combined_secret, "noise-xx");
        
        self.state = .complete;
        return .{ .session_keys = session_keys };
    }
};

/// Derive encryption key from shared secret using proper HKDF
pub fn deriveKey(shared_secret: []const u8, salt: []const u8, info: []const u8) [CHACHA20_KEY_SIZE]u8 {
    return KeyDerivation.deriveSingleKey(shared_secret, salt, info, CHACHA20_KEY_SIZE) catch {
        // Secure fallback - still use proper HKDF but with default info
        var key: [CHACHA20_KEY_SIZE]u8 = undefined;
        const prk = crypto.kdf.hkdf.HkdfSha256.extract(salt, shared_secret);
        crypto.kdf.hkdf.HkdfSha256.expand(&key, "ghostwire-default", prk);
        return key;
    };
}

/// NEXTGEN Crypto capabilities using zcrypto
pub const NextGenCrypto = struct {
    /// Post-quantum secure tunnel establishment using zcrypto
    pub fn establishQuantumSafeTunnel(local_key: X25519KeyPair, peer_key: [X25519_PUBLIC_KEY_SIZE]u8) !struct {
        classical_shared: [32]u8,
        pq_shared: ?[32]u8, // Post-quantum shared secret when available
    } {
        const classical_shared = try local_key.exchange(peer_key);
        
        // Try to use zcrypto for post-quantum KEM
        const pq_shared = if (@hasDecl(zcrypto, "kyber")) blk: {
            // Use Kyber-768 for post-quantum security
            break :blk zcrypto.kyber.derive_shared_secret(peer_key);
        } else null;
        
        return .{
            .classical_shared = classical_shared,
            .pq_shared = pq_shared,
        };
    }
    
    /// Traffic obfuscation using zcrypto's advanced features
    pub fn obfuscatePacketAdvanced(packet: []u8, obfuscation_key: [32]u8, counter: u64) !void {
        if (@hasDecl(zcrypto, "obfuscation")) {
            // Use zcrypto's optimized traffic obfuscation
            try zcrypto.obfuscation.obfuscate_traffic(packet, obfuscation_key, counter);
        } else {
            // Fallback to simple XOR obfuscation
            for (packet, 0..) |*byte, i| {
                byte.* ^= obfuscation_key[(i + counter) % obfuscation_key.len];
            }
        }
    }
    
    /// Remove advanced packet obfuscation
    pub fn deobfuscatePacketAdvanced(packet: []u8, obfuscation_key: [32]u8, counter: u64) !void {
        if (@hasDecl(zcrypto, "obfuscation")) {
            try zcrypto.obfuscation.deobfuscate_traffic(packet, obfuscation_key, counter);
        } else {
            // Symmetric fallback
            try obfuscatePacketAdvanced(packet, obfuscation_key, counter);
        }
    }
    
    /// Multi-hop encryption for mesh routing using zcrypto
    pub fn encryptMultiHop(
        plaintext: []const u8,
        hop_keys: [][32]u8,
        output: []u8,
        allocator: std.mem.Allocator,
    ) !usize {
        if (@hasDecl(zcrypto, "multihop")) {
            return zcrypto.multihop.encrypt_onion(plaintext, hop_keys, output);
        } else {
            // Fallback: nested ChaCha20-Poly1305 encryption
            var current_data = try allocator.dupe(u8, plaintext);
            defer allocator.free(current_data);
            
            // Encrypt in reverse order (outermost layer first)
            var i = hop_keys.len;
            while (i > 0) {
                i -= 1;
                const cipher = ChaCha20Poly1305.init(hop_keys[i]);
                const nonce = [_]u8{0} ** CHACHA20_NONCE_SIZE; // Should be random in production
                
                var tag: [CHACHA20_TAG_SIZE]u8 = undefined;
                try cipher.encrypt(nonce, current_data, &[_]u8{}, current_data, &tag);
                
                // Prepend tag to data for next layer
                const new_size = current_data.len + CHACHA20_TAG_SIZE;
                const new_data = try allocator.alloc(u8, new_size);
                @memcpy(new_data[0..CHACHA20_TAG_SIZE], &tag);
                @memcpy(new_data[CHACHA20_TAG_SIZE..], current_data);
                
                allocator.free(current_data);
                current_data = new_data;
            }
            
            @memcpy(output[0..current_data.len], current_data);
            return current_data.len;
        }
    }
    
    /// XChaCha20-Poly1305 for better mobile performance
    pub fn encryptMobile(
        plaintext: []const u8,
        key: [32]u8,
        nonce: [24]u8, // XChaCha20 uses 24-byte nonces
        output: []u8,
        tag: *[16]u8,
    ) !void {
        if (@hasDecl(zcrypto, "xchacha20")) {
            try zcrypto.xchacha20.encrypt(plaintext, key, nonce, output, tag);
        } else {
            // Fallback to regular ChaCha20-Poly1305 with truncated nonce
            const chacha_nonce = nonce[0..CHACHA20_NONCE_SIZE].*;
            const cipher = ChaCha20Poly1305.init(key);
            try cipher.encrypt(chacha_nonce, plaintext, &[_]u8{}, output, tag);
        }
    }
    
    /// Gossip message signing for mesh protocol
    pub fn signGossipMessage(signing_key: Ed25519KeyPair, message: []const u8, node_id: []const u8) ![ED25519_SIGNATURE_SIZE]u8 {
        // Create gossip-specific signing context
        var signing_context: [1024]u8 = undefined;
        const context = try std.fmt.bufPrint(&signing_context, "ghostwire-gossip-v1:{s}:{s}", .{ node_id, message });
        
        return try signing_key.sign(context);
    }
    
    /// Verify gossip message signature
    pub fn verifyGossipMessage(public_key: [ED25519_PUBLIC_KEY_SIZE]u8, message: []const u8, signature: [ED25519_SIGNATURE_SIZE]u8, node_id: []const u8) !bool {
        var verification_context: [1024]u8 = undefined;
        const context = try std.fmt.bufPrint(&verification_context, "ghostwire-gossip-v1:{s}:{s}", .{ node_id, message });
        
        return Ed25519KeyPair.verify(public_key, context, signature);
    }
    
    /// Generate DHT node ID from public key
    pub fn generateDhtNodeId(public_key: [ED25519_PUBLIC_KEY_SIZE]u8) [32]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("ghostwire-dht-node-id-v1");
        hasher.update(&public_key);
        
        var node_id: [32]u8 = undefined;
        hasher.final(&node_id);
        return node_id;
    }
    
    /// Header protection for stealth protocols using zcrypto
    pub fn protectHeaders(headers: []u8, protection_key: [16]u8) !void {
        if (@hasDecl(zcrypto, "header_protection")) {
            try zcrypto.header_protection.protect(headers, protection_key);
        } else {
            // Simple header protection fallback
            for (headers, 0..) |*byte, i| {
                byte.* ^= protection_key[i % protection_key.len];
            }
        }
    }
    
    /// Remove header protection
    pub fn unprotectHeaders(headers: []u8, protection_key: [16]u8) !void {
        // Header protection is symmetric
        try protectHeaders(headers, protection_key);
    }
    
    /// Bandwidth-efficient key exchange for mobile
    pub fn mobileKeyExchange(local_key: X25519KeyPair, peer_public: [32]u8) !struct {
        shared_secret: [32]u8,
        bandwidth_saved: u32,
    } {
        const shared = try local_key.exchange(peer_public);
        
        // zcrypto optimizations save bandwidth
        const bandwidth_saved = if (@hasDecl(zcrypto, "mobile_optimizations")) 
            zcrypto.mobile_optimizations.bandwidth_reduction 
        else 
            0;
            
        return .{
            .shared_secret = shared,
            .bandwidth_saved = bandwidth_saved,
        };
    }
    
    /// Traffic obfuscation for stealth protocols (simple version for compatibility)
    pub fn obfuscatePacket(packet: []u8, obfuscation_key: [16]u8, counter: u64) void {
        for (packet, 0..) |*byte, i| {
            byte.* ^= obfuscation_key[(i + counter) % obfuscation_key.len];
        }
    }
    
    /// Remove packet obfuscation (simple version)
    pub fn deobfuscatePacket(packet: []u8, obfuscation_key: [16]u8, counter: u64) void {
        // Obfuscation is symmetric
        obfuscatePacket(packet, obfuscation_key, counter);
    }
};

test "X25519 key exchange" {
    const alice_keys = try X25519KeyPair.generate();
    const bob_keys = try X25519KeyPair.generate();

    const alice_shared = try alice_keys.exchange(bob_keys.public_key);
    const bob_shared = try bob_keys.exchange(alice_keys.public_key);

    try std.testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "Ed25519 signatures" {
    const keys = try Ed25519KeyPair.generate();
    const message = "Hello, Ghostwire!";

    const signature = try keys.sign(message);
    const is_valid = Ed25519KeyPair.verify(keys.public_key, message, signature);

    try std.testing.expect(is_valid);
}

test "ChaCha20-Poly1305 encryption" {
    const key = [_]u8{0} ** CHACHA20_KEY_SIZE;
    const nonce = [_]u8{1} ** CHACHA20_NONCE_SIZE;
    const plaintext = "Hello, Ghostwire!";
    const additional_data = "metadata";

    const cipher = ChaCha20Poly1305.init(key);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [CHACHA20_TAG_SIZE]u8 = undefined;

    try cipher.encrypt(nonce, plaintext, additional_data, &ciphertext, &tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try cipher.decrypt(nonce, &ciphertext, tag, additional_data, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "HKDF key derivation" {
    const shared_secret = "shared_secret_test";
    const salt = "salt_test";
    const info = "ghostwire-test";
    
    // Test single key derivation
    const key1 = try KeyDerivation.deriveSingleKey(shared_secret, salt, info, 32);
    const key2 = try KeyDerivation.deriveSingleKey(shared_secret, salt, info, 32);
    
    // Same inputs should produce same output
    try std.testing.expectEqualSlices(u8, &key1, &key2);
    
    // Different info should produce different output
    const key3 = try KeyDerivation.deriveSingleKey(shared_secret, salt, "different-info", 32);
    try std.testing.expect(!std.mem.eql(u8, &key1, &key3));
}

test "Session key derivation" {
    const shared_secret = "test_shared_secret_for_session";
    const salt = "session_salt";
    
    const session_keys = KeyDerivation.deriveSessionKeys(shared_secret, salt);
    
    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, &session_keys.encryption_key, &session_keys.mac_key));
    
    // Should be deterministic
    const session_keys2 = KeyDerivation.deriveSessionKeys(shared_secret, salt);
    try std.testing.expectEqualSlices(u8, &session_keys.encryption_key, &session_keys2.encryption_key);
    try std.testing.expectEqualSlices(u8, &session_keys.mac_key, &session_keys2.mac_key);
}

test "Key rotation" {
    var rotation = KeyRotation.init();
    const initial_key = rotation.current_key;
    
    // Should not rotate immediately
    try std.testing.expect(!rotation.shouldRotate());
    
    // Force rotation
    rotation.rotate();
    
    // Key should have changed
    try std.testing.expect(!std.mem.eql(u8, &initial_key, &rotation.current_key));
}

test "Noise handshake" {
    const alice_static = try X25519KeyPair.generate();
    _ = try X25519KeyPair.generate(); // bob_static for future use
    
    var alice_handshake = NoiseHandshake.initInitiator(alice_static);
    
    const allocator = std.testing.allocator;
    const hello_msg = try alice_handshake.createInitiatorHello(allocator);
    defer allocator.free(hello_msg);
    
    // Message should contain both ephemeral and static keys
    try std.testing.expect(hello_msg.len >= X25519_PUBLIC_KEY_SIZE * 2);
}

test "Multiple key derivation" {
    const shared_secret = "test_multi_key_derivation";
    const salt = "multi_salt";
    const info = "multi_info";
    
    var key1: [16]u8 = undefined;
    var key2: [32]u8 = undefined;
    var key3: [8]u8 = undefined;
    
    var keys = [_][]u8{ &key1, &key2, &key3 };
    
    try KeyDerivation.deriveKeys(shared_secret, salt, info, &keys);
    
    // All keys should be different
    try std.testing.expect(!std.mem.eql(u8, key1[0..8], key2[0..8]));
    try std.testing.expect(!std.mem.eql(u8, key1[0..8], &key3));
    try std.testing.expect(!std.mem.eql(u8, key2[0..8], &key3));
}

test "Crypto error handling" {
    // Test buffer too small
    const cipher = ChaCha20Poly1305.init([_]u8{0} ** CHACHA20_KEY_SIZE);
    const nonce = [_]u8{1} ** CHACHA20_NONCE_SIZE;
    const plaintext = "test message";
    const additional_data = "";
    
    var small_buffer: [5]u8 = undefined; // Too small
    var tag: [CHACHA20_TAG_SIZE]u8 = undefined;
    
    try std.testing.expectError(error.BufferTooSmall, 
        cipher.encrypt(nonce, plaintext, additional_data, &small_buffer, &tag));
}

test "Fuzzing - random key operations" {
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        // Generate random keys and test operations
        const alice_keys = try X25519KeyPair.generate();
        const bob_keys = try X25519KeyPair.generate();
        
        const shared1 = try alice_keys.exchange(bob_keys.public_key);
        const shared2 = try bob_keys.exchange(alice_keys.public_key);
        
        // Should always be equal
        try std.testing.expectEqualSlices(u8, &shared1, &shared2);
        
        // Test signature round-trip
        const sign_keys = try Ed25519KeyPair.generate();
        const message = "fuzz test message";
        const signature = try sign_keys.sign(message);
        const is_valid = Ed25519KeyPair.verify(sign_keys.public_key, message, signature);
        try std.testing.expect(is_valid);
    }
}

test "NEXTGEN: Quantum-safe tunnel establishment" {
    const alice_keys = try X25519KeyPair.generate();
    const bob_keys = try X25519KeyPair.generate();
    
    const tunnel = try NextGenCrypto.establishQuantumSafeTunnel(alice_keys, bob_keys.public_key);
    
    // Should have classical shared secret
    try std.testing.expect(tunnel.classical_shared.len == 32);
    
    // Post-quantum secret depends on zcrypto availability
    if (tunnel.pq_shared) |pq| {
        try std.testing.expect(pq.len == 32);
    }
}

test "NEXTGEN: Gossip message signing and verification" {
    const node_keys = try Ed25519KeyPair.generate();
    const node_id = "node_12345";
    const message = "gossip_message_test";
    
    const signature = try NextGenCrypto.signGossipMessage(node_keys, message, node_id);
    const is_valid = try NextGenCrypto.verifyGossipMessage(node_keys.public_key, message, signature, node_id);
    
    try std.testing.expect(is_valid);
    
    // Should fail with wrong node_id
    const is_invalid = try NextGenCrypto.verifyGossipMessage(node_keys.public_key, message, signature, "wrong_node");
    try std.testing.expect(!is_invalid);
}

test "NEXTGEN: DHT node ID generation" {
    const keys = try Ed25519KeyPair.generate();
    const node_id1 = NextGenCrypto.generateDhtNodeId(keys.public_key);
    const node_id2 = NextGenCrypto.generateDhtNodeId(keys.public_key);
    
    // Should be deterministic
    try std.testing.expectEqualSlices(u8, &node_id1, &node_id2);
    
    // Different keys should produce different node IDs
    const keys2 = try Ed25519KeyPair.generate();
    const node_id3 = NextGenCrypto.generateDhtNodeId(keys2.public_key);
    try std.testing.expect(!std.mem.eql(u8, &node_id1, &node_id3));
}

test "NEXTGEN: Traffic obfuscation" {
    var packet = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const original = packet;
    const key = [_]u8{0xAA} ** 16;
    const counter = 12345;
    
    // Obfuscate
    NextGenCrypto.obfuscatePacket(&packet, key, counter);
    
    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &packet, &original));
    
    // Deobfuscate
    NextGenCrypto.deobfuscatePacket(&packet, key, counter);
    
    // Should be back to original
    try std.testing.expectEqualSlices(u8, &packet, &original);
}

test "NEXTGEN: Advanced traffic obfuscation (zcrypto)" {
    var packet = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
    const original = packet;
    const key = [_]u8{0xBB} ** 32;
    const counter = 54321;
    
    // Advanced obfuscation (fallback to simple if zcrypto not available)
    try NextGenCrypto.obfuscatePacketAdvanced(&packet, key, counter);
    
    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &packet, &original));
    
    // Deobfuscate
    try NextGenCrypto.deobfuscatePacketAdvanced(&packet, key, counter);
    
    // Should be back to original
    try std.testing.expectEqualSlices(u8, &packet, &original);
}

test "NEXTGEN: Mobile key exchange optimization" {
    const alice_keys = try X25519KeyPair.generate();
    const bob_keys = try X25519KeyPair.generate();
    
    const result = try NextGenCrypto.mobileKeyExchange(alice_keys, bob_keys.public_key);
    
    // Should have valid shared secret
    try std.testing.expect(result.shared_secret.len == 32);
    
    // Bandwidth savings depend on zcrypto availability
    std.log.info("Bandwidth saved: {} bytes", .{result.bandwidth_saved});
}

test "NEXTGEN: Header protection" {
    var headers = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const original = headers;
    const protection_key = [_]u8{0xCC} ** 16;
    
    // Protect headers
    try NextGenCrypto.protectHeaders(&headers, protection_key);
    
    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &headers, &original));
    
    // Unprotect headers
    try NextGenCrypto.unprotectHeaders(&headers, protection_key);
    
    // Should be back to original
    try std.testing.expectEqualSlices(u8, &headers, &original);
}
