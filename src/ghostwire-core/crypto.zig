//! Cryptographic primitives for Ghostwire
//!
//! Implements the crypto stack including:
//! - X25519 key exchange
//! - Ed25519 signatures
//! - ChaCha20-Poly1305 authenticated encryption
//! - Key derivation and rotation

const std = @import("std");
const crypto = std.crypto;

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
        var private_key: [X25519_PRIVATE_KEY_SIZE]u8 = undefined;
        crypto.random.bytes(&private_key);

        const public_key = crypto.dh.X25519.scalarmultBase(private_key);

        return X25519KeyPair{
            .public_key = public_key,
            .private_key = private_key,
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
        const key_pair = try crypto.sign.Ed25519.KeyPair.create(null);
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

/// Derive encryption key from shared secret using HKDF
pub fn deriveKey(shared_secret: []const u8, salt: []const u8, info: []const u8) [CHACHA20_KEY_SIZE]u8 {
    var key: [CHACHA20_KEY_SIZE]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.extract(&key, shared_secret, salt);
    // TODO: Implement proper HKDF expand step with info
    return key;
}

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
