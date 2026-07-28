use tracing::{debug, error, info, warn};
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, VapidSignatureBuilder,
    WebPushClient, WebPushMessageBuilder,
};

/// VAPID key pair for Web Push authentication.
///
/// Keys are loaded from environment variables on startup:
/// - `VAPID_PRIVATE_KEY`: PEM-encoded ECDSA P-256 private key (or path to PEM file)
/// - `VAPID_PUBLIC_KEY`: base64url-encoded ECDSA P-256 public key (for clients)
///
/// If not set, web push is disabled (no error -- optional feature).
pub struct WebPushSender {
    /// The raw PEM bytes of the private key, kept in memory for signing.
    private_key_pem: Vec<u8>,
    /// The base64url-encoded public key to hand out to browser clients.
    public_key_base64: String,
    client: IsahcWebPushClient,
}

impl WebPushSender {
    /// Create a new WebPushSender from environment variables.
    ///
    /// Returns `None` if VAPID keys are not configured.
    pub fn from_env() -> Option<Self> {
        let private_key_source = match std::env::var("VAPID_PRIVATE_KEY") {
            Ok(k) => k,
            Err(_) => {
                info!("WebPushSender: VAPID_PRIVATE_KEY not set, web push disabled");
                return None;
            }
        };

        let public_key_b64 = match std::env::var("VAPID_PUBLIC_KEY") {
            Ok(k) => k,
            Err(_) => {
                error!("WebPushSender: VAPID_PUBLIC_KEY not set (but private key is). Web push disabled.");
                return None;
            }
        };

        // The private key can be either inline PEM or a path to a PEM file.
        let private_key_pem = if private_key_source.starts_with("-----") {
            // Inline PEM
            private_key_source.into_bytes()
        } else {
            // File path
            match std::fs::read(&private_key_source) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!(
                        "WebPushSender: Failed to read VAPID private key file {}: {}",
                        private_key_source, e
                    );
                    return None;
                }
            }
        };

        let client = match IsahcWebPushClient::new() {
            Ok(c) => c,
            Err(e) => {
                error!("WebPushSender: Failed to create HTTP client: {}", e);
                return None;
            }
        };

        info!("WebPushSender: VAPID keys loaded, web push enabled");

        Some(Self {
            private_key_pem,
            public_key_base64: public_key_b64,
            client,
        })
    }

    /// Get the public VAPID key (base64url-encoded) for the client.
    pub fn public_key(&self) -> &str {
        &self.public_key_base64
    }

    /// Send a web push notification to a browser subscription.
    ///
    /// `endpoint` is the push service URL from the browser's PushSubscription.
    /// `p256dh` and `auth` are the subscription keys (base64url-encoded).
    /// `payload` is the JSON notification body.
    ///
    /// Returns true on success, false on failure.
    pub async fn send(
        &self,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
        payload: &[u8],
    ) -> bool {
        let subscription = SubscriptionInfo::new(endpoint, p256dh, auth);

        let sig_builder = match VapidSignatureBuilder::from_pem(
            std::io::Cursor::new(&self.private_key_pem),
            &subscription,
        ) {
            Ok(b) => b,
            Err(e) => {
                error!("WebPushSender: Failed to build VAPID signature: {}", e);
                return false;
            }
        };

        let signature = match sig_builder.build() {
            Ok(s) => s,
            Err(e) => {
                error!("WebPushSender: Failed to sign VAPID: {}", e);
                return false;
            }
        };

        let mut builder = WebPushMessageBuilder::new(&subscription);
        builder.set_vapid_signature(signature);
        builder.set_payload(ContentEncoding::Aes128Gcm, payload);

        let message = match builder.build() {
            Ok(m) => m,
            Err(e) => {
                error!("WebPushSender: Failed to build push message: {}", e);
                return false;
            }
        };

        match self.client.send(message).await {
            Ok(()) => {
                debug!("WebPushSender: Push sent to {}", endpoint);
                true
            }
            Err(e) => {
                warn!("WebPushSender: Push failed for {}: {}", endpoint, e);
                false
            }
        }
    }
}
