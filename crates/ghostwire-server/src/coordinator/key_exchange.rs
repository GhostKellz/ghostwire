/// Key exchange and cryptographic operations
///
/// Handles key management and distribution with:
/// - WireGuard key validation
/// - Key rotation support
/// - Secure key storage
/// - Key exchange protocols

use ghostwire_common::{
    error::{Result, GhostWireError},
    types::*,
};
use tracing::{debug, warn};

/// Key exchange manager
pub struct KeyExchangeManager;

impl KeyExchangeManager {
    /// Validate WireGuard public key
    pub fn validate_public_key(key: &[u8]) -> Result<PublicKey> {
        if key.len() != 32 {
            return Err(GhostWireError::validation("Public key must be 32 bytes"));
        }

        // Basic validation - ensure it's not all zeros
        if key.iter().all(|&b| b == 0) {
            return Err(GhostWireError::validation("Invalid public key: all zeros"));
        }

        // Ensure it's not the identity element
        let identity = [0u8; 32];
        if key == identity {
            return Err(GhostWireError::validation("Invalid public key: identity element"));
        }

        Ok(PublicKey(key.try_into().map_err(|_| {
            GhostWireError::validation("Invalid public key format")
        })?))
    }

    /// Generate a new WireGuard key pair (for testing/admin purposes)
    pub fn generate_keypair() -> Result<(PublicKey, PrivateKey)> {
        use x25519_dalek::{EphemeralSecret, PublicKey as DalekPublic};

        let private = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = DalekPublic::from(&private);

        let private_key = PrivateKey(private.to_bytes());
        let public_key = PublicKey(public.to_bytes());

        debug!("Generated new WireGuard key pair");

        Ok((public_key, private_key))
    }

    /// Validate that a private key corresponds to a public key
    pub fn validate_keypair(public_key: &PublicKey, private_key: &PrivateKey) -> Result<bool> {
        use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};

        let secret = StaticSecret::from(private_key.0);
        let derived_public = DalekPublic::from(&secret);

        Ok(derived_public.as_bytes() == &public_key.0)
    }

    /// Compute shared secret between two keys (for DERP relay encryption)
    pub fn compute_shared_secret(
        private_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<[u8; 32]> {
        use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};

        let secret = StaticSecret::from(private_key.0);
        let public = DalekPublic::from(public_key.0);

        let shared = secret.diffie_hellman(&public);

        Ok(*shared.as_bytes())
    }

    /// Create a pre-shared key for additional security
    pub fn generate_preshared_key() -> [u8; 32] {
        rand::random()
    }

    /// Validate a pre-shared key
    pub fn validate_preshared_key(psk: &[u8]) -> Result<()> {
        if psk.len() != 32 {
            return Err(GhostWireError::validation("Pre-shared key must be 32 bytes"));
        }

        // Ensure it's not all zeros (which would disable the PSK)
        if psk.iter().all(|&b| b == 0) {
            warn!("Pre-shared key is all zeros - PSK will be disabled");
        }

        Ok(())
    }

    /// Derive a session key from shared secret and additional data
    pub fn derive_session_key(
        shared_secret: &[u8; 32],
        additional_data: &[u8],
    ) -> Result<[u8; 32]> {
        use blake3::Hasher;

        let mut hasher = Hasher::new();
        hasher.update(shared_secret);
        hasher.update(additional_data);
        hasher.update(b"ghostwire-session");

        let mut key = [0u8; 32];
        key.copy_from_slice(hasher.finalize().as_bytes());

        Ok(key)
    }

    /// Constant-time comparison of keys
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;

        if a.len() != b.len() {
            return false;
        }

        a.ct_eq(b).into()
    }

    /// Sanitize key for logging (show only first/last few bytes)
    pub fn sanitize_key_for_log(key: &[u8]) -> String {
        if key.len() >= 8 {
            format!("{}...{}",
                    hex::encode(&key[..4]),
                    hex::encode(&key[key.len()-4..]))
        } else {
            "****".to_string()
        }
    }
}

/// Key rotation manager
pub struct KeyRotationManager {
    rotation_interval: std::time::Duration,
}

impl KeyRotationManager {
    /// Create new key rotation manager
    pub fn new(rotation_interval: std::time::Duration) -> Self {
        Self { rotation_interval }
    }

    /// Check if a key needs rotation based on age
    pub fn needs_rotation(&self, key_created: std::time::SystemTime) -> bool {
        std::time::SystemTime::now()
            .duration_since(key_created)
            .unwrap_or_default() > self.rotation_interval
    }

    /// Generate rotation schedule for a key
    pub fn next_rotation_time(
        &self,
        key_created: std::time::SystemTime,
    ) -> std::time::SystemTime {
        key_created + self.rotation_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_public_key() {
        // Valid key
        let valid_key = [1u8; 32];
        assert!(KeyExchangeManager::validate_public_key(&valid_key).is_ok());

        // Invalid length
        let short_key = [1u8; 16];
        assert!(KeyExchangeManager::validate_public_key(&short_key).is_err());

        // All zeros (invalid)
        let zero_key = [0u8; 32];
        assert!(KeyExchangeManager::validate_public_key(&zero_key).is_err());
    }

    #[test]
    fn test_generate_keypair() {
        let (public, private) = KeyExchangeManager::generate_keypair().unwrap();

        // Keys should be different
        assert_ne!(public.0, [0u8; 32]);
        assert_ne!(private.0, [0u8; 32]);

        // Should be valid keypair
        assert!(KeyExchangeManager::validate_keypair(&public, &private).unwrap());
    }

    #[test]
    fn test_key_sanitization() {
        let key = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                   0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                   0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

        let sanitized = KeyExchangeManager::sanitize_key_for_log(&key);
        assert_eq!(sanitized, "12345678...66778899");
    }
}