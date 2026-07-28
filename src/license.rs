use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use tracing::{info, warn};

/// Hardcoded public key for license verification.
/// Only the official Honmoon deployment has a valid signed license.
const PUBLIC_KEY_B64: &str = "yIenPQKahioRl6ytTgNh/lKMSTYTGrjns/mYD0Mc7jA=";

/// Expected license payload
const LICENSE_PAYLOAD: &[u8] = b"honmoon-server-license-v1";

/// Verify the SERVER_LICENSE env var against the hardcoded public key.
/// Returns true if the license is valid (official deployment).
pub fn verify_license(license_token: &str) -> bool {
    let parts: Vec<&str> = license_token.split('.').collect();
    if parts.len() != 2 {
        warn!("Invalid license format");
        return false;
    }

    let payload = match STANDARD.decode(parts[0]) {
        Ok(p) => p,
        Err(_) => {
            warn!("Invalid license payload encoding");
            return false;
        }
    };

    if payload != LICENSE_PAYLOAD {
        warn!("Invalid license payload");
        return false;
    }

    let sig_bytes = match STANDARD.decode(parts[1]) {
        Ok(s) => s,
        Err(_) => {
            warn!("Invalid license signature encoding");
            return false;
        }
    };

    let pub_key_bytes = match STANDARD.decode(PUBLIC_KEY_B64) {
        Ok(b) => b,
        Err(_) => {
            warn!("Invalid hardcoded public key");
            return false;
        }
    };

    let pub_key_arr: [u8; 32] = match pub_key_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            warn!("Public key wrong length");
            return false;
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&pub_key_arr) {
        Ok(k) => k,
        Err(_) => {
            warn!("Invalid public key");
            return false;
        }
    };

    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            warn!("Signature wrong length");
            return false;
        }
    };

    let signature = Signature::from_bytes(&sig_arr);

    match verifying_key.verify(&payload, &signature) {
        Ok(()) => {
            info!("Server license verified — billing features enabled");
            true
        }
        Err(_) => {
            warn!("License signature verification failed");
            false
        }
    }
}
