use crate::error::AppError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct CryptoManager {
    key_bytes: [u8; 32],
}

impl CryptoManager {
    pub fn new(secret: &str) -> Self {
        let digest = Sha256::digest(secret.as_bytes());
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(&digest[..32]);
        Self { key_bytes }
    }

    pub fn encrypt_bytes(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<String, AppError> {
        let cipher = XChaCha20Poly1305::new((&self.key_bytes).into());

        let mut nonce = [0_u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| AppError::Crypto("encrypt failed".to_string()))?;

        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
        let ct_b64 = URL_SAFE_NO_PAD.encode(ciphertext);

        Ok(format!("v1.{nonce_b64}.{ct_b64}"))
    }

    pub fn decrypt_bytes(&self, token: &str, aad: Option<&[u8]>) -> Result<Vec<u8>, AppError> {
        let mut parts = token.split('.');
        let version = parts
            .next()
            .ok_or_else(|| AppError::Crypto("invalid token format".to_string()))?;
        let nonce_b64 = parts
            .next()
            .ok_or_else(|| AppError::Crypto("invalid token format".to_string()))?;
        let ct_b64 = parts
            .next()
            .ok_or_else(|| AppError::Crypto("invalid token format".to_string()))?;

        if version != "v1" || parts.next().is_some() {
            return Err(AppError::Crypto("invalid token format".to_string()));
        }

        let nonce = URL_SAFE_NO_PAD
            .decode(nonce_b64)
            .map_err(|_| AppError::Crypto("invalid nonce encoding".to_string()))?;
        if nonce.len() != 24 {
            return Err(AppError::Crypto("invalid nonce size".to_string()));
        }

        let ciphertext = URL_SAFE_NO_PAD
            .decode(ct_b64)
            .map_err(|_| AppError::Crypto("invalid ciphertext encoding".to_string()))?;

        let cipher = XChaCha20Poly1305::new((&self.key_bytes).into());

        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad.unwrap_or(&[]),
                },
            )
            .map_err(|_| AppError::Crypto("decrypt failed".to_string()))
    }

    pub fn encrypt_string(&self, plaintext: &str, aad: Option<&[u8]>) -> Result<String, AppError> {
        self.encrypt_bytes(plaintext.as_bytes(), aad)
    }

    pub fn decrypt_to_string(&self, token: &str, aad: Option<&[u8]>) -> Result<String, AppError> {
        let bytes = self.decrypt_bytes(token, aad)?;
        String::from_utf8(bytes)
            .map_err(|_| AppError::Crypto("invalid utf-8 plaintext".to_string()))
    }
}

pub fn blind_index_string(secret: &str, value: &str) -> Result<String, AppError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Crypto("invalid blind index key".to_string()))?;
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{blind_index_string, CryptoManager};

    #[test]
    fn encrypt_decrypt_roundtrip_with_aad() {
        let manager = CryptoManager::new("unit-test-secret");
        let aad = b"context-aad";

        let token = manager
            .encrypt_string("hello haven", Some(aad))
            .expect("encryption should succeed");

        let plaintext = manager
            .decrypt_to_string(&token, Some(aad))
            .expect("decryption should succeed");

        assert_eq!(plaintext, "hello haven");
        assert!(token.starts_with("v1."));
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let manager = CryptoManager::new("unit-test-secret");
        let token = manager
            .encrypt_string("payload", Some(b"aad-1"))
            .expect("encryption should succeed");

        let err = manager
            .decrypt_to_string(&token, Some(b"aad-2"))
            .expect_err("decryption should fail for wrong aad");

        assert!(err.to_string().contains("decrypt failed"));
    }

    #[test]
    fn decrypt_rejects_invalid_token_format() {
        let manager = CryptoManager::new("unit-test-secret");

        let err = manager
            .decrypt_to_string("invalid-format", None)
            .expect_err("invalid token format must fail");

        assert!(err.to_string().contains("invalid token format"));
    }

    #[test]
    fn blind_index_is_deterministic() {
        let left =
            blind_index_string("blind-index-key", "user@example.com").expect("index should work");
        let right =
            blind_index_string("blind-index-key", "user@example.com").expect("index should work");

        assert_eq!(left, right);
        assert_ne!(left, "user@example.com");
    }
}
