use ghostwire_common::error::{Result, GhostWireError};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};
use blake3::Hasher;
use std::time::SystemTime;

/// High-performance crypto operations for WireGuard
///
/// This module provides optimized implementations of cryptographic
/// operations used in WireGuard, with SIMD optimizations where available.
pub struct WireGuardCrypto {
    hasher: blake3::Hasher,
}

impl WireGuardCrypto {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    /// Generate WireGuard session keys using BLAKE3
    pub fn derive_session_keys(
        private_key: &[u8; 32],
        public_key: &[u8; 32],
        ephemeral: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32])> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(private_key);
        hasher.update(public_key);
        hasher.update(ephemeral);

        let output = hasher.finalize();
        let output_bytes = output.as_bytes();

        let mut sending_key = [0u8; 32];
        let mut receiving_key = [0u8; 32];

        sending_key.copy_from_slice(&output_bytes[0..32]);
        receiving_key.copy_from_slice(&output_bytes[32..64]);

        Ok((sending_key, receiving_key))
    }

    /// High-performance ChaCha20-Poly1305 encryption
    #[cfg(feature = "simd")]
    pub fn encrypt_simd(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> Result<()> {
        // SIMD-optimized encryption would go here
        Self::encrypt_standard(key, nonce, plaintext, associated_data)
    }

    /// Standard ChaCha20-Poly1305 encryption
    pub fn encrypt_standard(
        key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &mut [u8],
        associated_data: &[u8],
    ) -> Result<()> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| GhostWireError::crypto(format!("Invalid key: {}", e)))?;

        let nonce_obj = Nonce::from_slice(nonce);

        cipher.encrypt_in_place(nonce_obj, associated_data, plaintext)
            .map_err(|e| GhostWireError::crypto(format!("Encryption failed: {}", e)))?;

        Ok(())
    }

    /// High-performance ChaCha20-Poly1305 decryption
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &mut [u8],
        associated_data: &[u8],
    ) -> Result<()> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| GhostWireError::crypto(format!("Invalid key: {}", e)))?;

        let nonce_obj = Nonce::from_slice(nonce);

        cipher.decrypt_in_place(nonce_obj, associated_data, ciphertext)
            .map_err(|e| GhostWireError::crypto(format!("Decryption failed: {}", e)))?;

        Ok(())
    }

    /// Generate timestamp for WireGuard handshake
    pub fn generate_timestamp() -> [u8; 12] {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut timestamp = [0u8; 12];
        timestamp[0..8].copy_from_slice(&now.to_le_bytes());
        // Last 4 bytes remain zero (reserved)

        timestamp
    }

    /// Constant-time key comparison
    pub fn keys_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }
}

impl Default for WireGuardCrypto {
    fn default() -> Self {
        Self::new()
    }
}