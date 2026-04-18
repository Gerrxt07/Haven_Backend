use crate::error::AppError;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use dashmap::DashMap;
use rand::RngCore;
use srp::groups::G_2048;
use srp::server::SrpServer;
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
        // Create SRP server with the same 2048-bit group used by the client
        let server = SrpServer::<sha2::Sha256>::new(&G_2048);

        // Generate server ephemeral private key (b)
        let mut server_private_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut server_private_key);

        // Compute server public ephemeral (B)
        let server_public_key_b = server.compute_public_ephemeral(&server_private_key, &verifier);

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

        // Create SRP server
        let server = SrpServer::<sha2::Sha256>::new(&G_2048);

        // Process client reply to create verifier
        let verifier = server
            .process_reply(
                &ephemeral_data.server_private_key,
                &ephemeral_data.verifier,
                &client_public_key_a,
            )
            .map_err(|_| AppError::Unauthorized)?;

        // Verify client proof (M1)
        verifier
            .verify_client(&client_proof_m1)
            .map_err(|_| AppError::Unauthorized)?;

        // Get server proof (M2) to send to client
        let server_proof_m2 = verifier.proof().to_vec();

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

        let result = service.verify_challenge(&challenge_id, "other@example.com", vec![1], vec![2]);

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}
