use crate::error::AppError;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use dashmap::DashMap;
use num_bigint::BigUint;
use rand::RngCore;
use srp::groups::G_2048;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// SRP ephemeral key data stored temporarily during login handshake
#[derive(Clone)]
pub struct SrpEphemeralData {
    pub server_private_key: Vec<u8>,
    pub client_email: String,
    pub verifier: Vec<u8>,
    pub created_at: Instant,
}

/// SRP Service for handling SRP-6a authentication
#[derive(Clone)]
pub struct SrpService {
    /// Temporary storage for ephemeral keys during login handshake
    /// Key: challenge_id (random UUID), Value: ephemeral data
    ephemeral_store: Arc<DashMap<String, SrpEphemeralData>>,
    /// TTL for ephemeral data (5 minutes)
    ttl: Duration,
}

impl SrpService {
    pub fn new() -> Self {
        let service = Self {
            ephemeral_store: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(300), // 5 minutes
        };

        // Start cleanup task
        service.start_cleanup_task();

        service
    }

    /// Generate a random challenge ID
    pub fn generate_challenge_id() -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Step 1: Generate server ephemeral keys for login challenge
    ///
    /// # Arguments
    /// * `email` - User's email (used as identity)
    /// * `verifier` - SRP verifier (base64 decoded)
    ///
    /// # Returns
    /// * `(challenge_id, server_public_key_b)` - Store challenge_id temporarily, return server_public_key_b to client
    pub fn generate_challenge(
        &self,
        email: &str,
        verifier: Vec<u8>,
    ) -> Result<(String, String), AppError> {
        // Generate server ephemeral private key (b)
        let mut server_private_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_private_key);

        // Compute server public ephemeral (B)
        let server_public_key_b = compute_server_public_ephemeral(&server_private_key, &verifier);

        // Generate challenge ID
        let challenge_id = Self::generate_challenge_id();

        // Store ephemeral data
        let ephemeral_data = SrpEphemeralData {
            server_private_key: server_private_key.to_vec(),
            client_email: email.to_string(),
            verifier,
            created_at: Instant::now(),
        };

        self.ephemeral_store
            .insert(challenge_id.clone(), ephemeral_data);

        // Encode public key for transmission
        let server_public_key_b_b64 = STANDARD.encode(&server_public_key_b);

        Ok((challenge_id, server_public_key_b_b64))
    }

    /// Step 2: Verify client proof and generate server proof
    ///
    /// # Arguments
    /// * `challenge_id` - The challenge ID from step 1
    /// * `client_public_key_a` - Client's public key A (base64 decoded)
    /// * `client_proof_m1` - Client's proof M1 (base64 decoded)
    ///
    /// # Returns
    /// * `server_proof_m2` - Server's proof M2 to send to client
    pub fn verify_challenge(
        &self,
        challenge_id: &str,
        expected_email: &str,
        salt: &[u8],
        client_public_key_a: Vec<u8>,
        client_proof_m1: Vec<u8>,
    ) -> Result<Vec<u8>, AppError> {
        // Retrieve and remove ephemeral data (one-time use)
        let ephemeral_data = self
            .ephemeral_store
            .remove(challenge_id)
            .map(|(_, v)| v)
            .ok_or_else(|| AppError::Unauthorized)?;

        // Check if expired
        if ephemeral_data.created_at.elapsed() > self.ttl {
            return Err(AppError::Unauthorized);
        }

        if ephemeral_data.client_email != expected_email {
            return Err(AppError::Unauthorized);
        }

        let server_public_key_b =
            compute_server_public_ephemeral(&ephemeral_data.server_private_key, &ephemeral_data.verifier);
        let premaster_secret = compute_premaster_secret(
            &ephemeral_data.server_private_key,
            &ephemeral_data.verifier,
            &client_public_key_a,
            &server_public_key_b,
        )
        .ok_or(AppError::Unauthorized)?;
        let expected_client_proof = compute_js_client_proof(
            expected_email.as_bytes(),
            salt,
            &client_public_key_a,
            &server_public_key_b,
            &premaster_secret,
        );

        if expected_client_proof != client_proof_m1 {
            return Err(AppError::Unauthorized);
        }

        let session_key = sha256_bytes(&[&premaster_secret]);
        let server_proof_m2 =
            sha256_bytes(&[&client_public_key_a, &expected_client_proof, &session_key]);

        Ok(server_proof_m2)
    }

    /// Clean up expired ephemeral data periodically
    fn start_cleanup_task(&self) {
        let store = self.ephemeral_store.clone();
        let ttl = self.ttl;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                let now = Instant::now();
                store.retain(|_, data| now.duration_since(data.created_at) < ttl);
            }
        });
    }
}

fn sha256_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().to_vec()
}

fn xor_bytes(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter()
        .zip(right.iter())
        .map(|(l, r)| l ^ r)
        .collect()
}

fn compute_js_k() -> BigUint {
    BigUint::from_bytes_be(&sha256_bytes(&[&G_2048.n.to_bytes_be(), &G_2048.g.to_bytes_be()]))
}

fn compute_u(client_public_key_a: &[u8], server_public_key_b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&sha256_bytes(&[client_public_key_a, server_public_key_b]))
}

fn compute_server_public_ephemeral(server_private_key: &[u8], verifier: &[u8]) -> Vec<u8> {
    let b = BigUint::from_bytes_be(server_private_key);
    let v = BigUint::from_bytes_be(verifier);
    let k = compute_js_k();
    let public = ((k * &v) + G_2048.g.modpow(&b, &G_2048.n)) % &G_2048.n;
    public.to_bytes_be()
}

fn compute_premaster_secret(
    server_private_key: &[u8],
    verifier: &[u8],
    client_public_key_a: &[u8],
    server_public_key_b: &[u8],
) -> Option<Vec<u8>> {
    let a_pub = BigUint::from_bytes_be(client_public_key_a);
    if &a_pub % &G_2048.n == BigUint::default() {
        return None;
    }

    let b = BigUint::from_bytes_be(server_private_key);
    let v = BigUint::from_bytes_be(verifier);
    let u = compute_u(client_public_key_a, server_public_key_b);
    let premaster = (a_pub * v.modpow(&u, &G_2048.n))
        .modpow(&b, &G_2048.n)
        .to_bytes_be();
    Some(premaster)
}

fn compute_js_client_proof(
    identity: &[u8],
    salt: &[u8],
    client_public_key_a: &[u8],
    server_public_key_b: &[u8],
    premaster_secret: &[u8],
) -> Vec<u8> {
    let h_n = sha256_bytes(&[&G_2048.n.to_bytes_be()]);
    let h_g = sha256_bytes(&[&G_2048.g.to_bytes_be()]);
    let h_i = sha256_bytes(&[identity]);
    let session_key = sha256_bytes(&[premaster_secret]);
    let h_n_xor_h_g = xor_bytes(&h_n, &h_g);

    sha256_bytes(&[
        &h_n_xor_h_g,
        &h_i,
        salt,
        client_public_key_a,
        server_public_key_b,
        &session_key,
    ])
}

impl Default for SrpService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge_id() {
        let id1 = SrpService::generate_challenge_id();
        let id2 = SrpService::generate_challenge_id();
        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
        assert!(!id1.contains('+'));
        assert!(!id1.contains('/'));
        assert!(!id1.contains('='));
    }

    #[test]
    fn reject_mismatched_identity() {
        let service = SrpService {
            ephemeral_store: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(300),
        };
        let challenge_id = "challenge".to_string();
        service.ephemeral_store.insert(
            challenge_id.clone(),
            SrpEphemeralData {
                server_private_key: vec![1],
                client_email: "user@example.com".to_string(),
                verifier: vec![3],
                created_at: Instant::now(),
            },
        );

        let result = service.verify_challenge(
            &challenge_id,
            "other@example.com",
            b"salt",
            vec![1],
            vec![2],
        );

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[test]
    fn compute_js_client_proof_matches_known_js_vector() {
        let identity = b"gerrxt07@proton.me";
        let salt = hex::decode(
            "f20bfa943221cf583e1a979838209b6cd34ae1bb5fbd5b9ed104ab8d8961f065",
        )
        .unwrap();
        let verifier = hex::decode(
            "76f8344885f3f668d973dc8b2d9cfd5e8f526d70d98eab1050c42cb712a9e2af34fe29209fec620ce5afbe35ffa5328550fa71728c6c22e036a0bbb24885c554592b5f2cd41c00565e934968484cb2a4af406cb0425e7ae3347762dd127fe89a734f0fcc907c27e58dc989ea352c8484b84ac8a629f3b4eeadd76d26a003d57e13834e2fc12ab88ce7d64623a2f8451e4ecfbba4697e7d77c0e22dc10a7691b8652e0dc2eb4b3b205994328239a347d95b46e7e6a66cc8aeda0895bbee4ee9bee542c3655e97ddc7368386395369ad9e61967ffe0c6c62d9425b826b8cdfc64ab3640e8609f982acfc461fb3cf2b60417662a12002cec9db1a72c275e80b57b1",
        )
        .unwrap();
        let client_public_key_a = hex::decode(
            "3a9c06a4c898a5c5d153a95b344b4750997ee4752f89796fed01a9d3f0ae08722bcb3d0292dbb5dba740e47195599bebc2d0b5fcb3662f82bdccd6412218773aa46310a39f42b7c5c6116446bf17156583c50d7f72a81cb29d485937c0209a47a3b82cba31ca8314a635d72ed72af56f37750387406593b733cb45f2b49cb8d1dd4c1524f4d6c1d3beb5a34922b22dfdd4fb8aa5e3a57b12a6588a4308327348828141964f2a8ff8e065f1f5457da7bb9fef4006412d49115bab6926648e73bc0af52fc92f8b7df9e6e8dd374a9e1bb815ffeea84cc876bf0f48be15694cdc9538979e3fbf7a0ebd2456793e6e7bc6d3583d607eecac046d292e8aa3ef535386",
        )
        .unwrap();
        let server_private_key = [7u8; 32];
        let server_public_key_b = compute_server_public_ephemeral(&server_private_key, &verifier);
        let premaster_secret = compute_premaster_secret(
            &server_private_key,
            &verifier,
            &client_public_key_a,
            &server_public_key_b,
        )
        .unwrap();

        let proof = compute_js_client_proof(
            identity,
            &salt,
            &client_public_key_a,
            &server_public_key_b,
            &premaster_secret,
        );

        assert_eq!(
            hex::encode(proof),
            "eabe208672d6e91bad43d12888b9a994d82aa3a7526f65fedc1d1d8368033848"
        );
    }
}
