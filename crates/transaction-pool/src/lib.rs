/// Encryption manager for handling cryptographic operations
pub struct EncryptionManager {
    current_key: Arc<RwLock<Key<Aes256Gcm>>>,
    key_rotation_timestamp: Arc<RwLock<u64>>,
}

impl EncryptionManager {
    pub fn new() -> Self {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        Self {
            current_key: Arc::new(RwLock::new(Key::from_slice(&key_bytes))),
            key_rotation_timestamp: Arc::new(RwLock::new(current_timestamp())),
        }
    }

    pub async fn encrypt_intent(&self, payload: &[u8]) -> Result<(Vec<u8>, EncryptionMetadata), IntentError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let key = self.current_key.read().await;
        let cipher = Aes256Gcm::new(&key);

        let encrypted = cipher
            .encrypt(nonce, payload)
            .map_err(|_| IntentError::EncryptionFailed)?;

        let metadata = EncryptionMetadata {
            key_id: generate_key_id(),
            nonce: nonce_bytes.to_vec(),
            timestamp: current_timestamp(),
            algorithm: "AES-256-GCM".to_string(),
        };

        Ok((encrypted, metadata))
    }

    pub async fn decrypt_intent(&self, encrypted: &[u8], metadata: &EncryptionMetadata) -> Result<Vec<u8>, IntentError> {
        let key = self.current_key.read().await;
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&metadata.nonce);

        cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| IntentError::DecryptionFailed)
    }
}

/// GossipNetwork implementation for P2P communication
#[async_trait::async_trait]
pub trait GossipNetwork: Send + Sync + 'static {
    async fn broadcast(&self, message: String) -> Result<(), GossipError>;
    async fn subscribe(&self) -> mpsc::Receiver<GossipMessage>;
}

/// In-memory implementation of GossipNetwork for testing
pub struct InMemoryGossipNetwork {
    subscribers: Arc<RwLock<Vec<mpsc::Sender<GossipMessage>>>>,
}

impl InMemoryGossipNetwork {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl GossipNetwork for InMemoryGossipNetwork {
    async fn broadcast(&self, message: String) -> Result<(), GossipError> {
        let parsed_message: GossipMessage = serde_json::from_str(&message)
            .map_err(|_| GossipError::InvalidMessage)?;
        
        let subscribers = self.subscribers.read().await;
        for subscriber in subscribers.iter() {
            if let Err(e) = subscriber.send(parsed_message.clone()).await {
                error!("Failed to send message to subscriber: {}", e);
            }
        }
        Ok(())
    }

    async fn subscribe(&self) -> mpsc::Receiver<GossipMessage> {
        let (tx, rx) = mpsc::channel(100);
        self.subscribers.write().await.push(tx);
        rx
    }
}

impl EncryptedMempool {
    /// Starts the background tasks for the mempool
    pub async fn start_background_tasks(&self) -> JoinHandle<()> {
        let mempool = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = mempool.cleanup_expired_intents().await {
                    error!("Failed to cleanup expired intents: {:?}", e);
                }
            }
        })
    }

    /// Cleans up expired intents
    async fn cleanup_expired_intents(&self) -> Result<(), IntentError> {
        let now = current_timestamp();
        let mut intents = self.intents.write().await;
        let mut expired = Vec::new();

        intents.retain(|id, intent| {
            if intent.metadata.expiry <= now {
                expired.push(id.clone());
                false
            } else {
                true
            }
        });

        // Broadcast expiration messages
        for intent_id in expired {
            let msg = GossipMessage::Intent {
                message_type: IntentMessageType::Expiration,
                intent_id,
                metadata: None,
                payload_hash: None,
            };
            self.broadcast_gossip_message(msg).await;
        }

        Ok(())
    }

    /// Stores a partial solution from a solver
    async fn store_partial_solution(
        &self,
        intent_id: String,
        solver_id: String,
        partial_solution: Vec<u8>,
    ) -> Result<(), IntentError> {
        let mut intents = self.intents.write().await;
        let intent = intents.get_mut(&intent_id).ok_or(IntentError::NotFound)?;
        
        // Store the partial solution in the intent's metadata
        intent.metadata.solution_metadata = Some(partial_solution);
        
        // Update metrics
        counter!("mempool.partial_solutions").increment(1);
        
        Ok(())
    }
}

// Expanded error types
#[derive(Debug)]
pub enum IntentError {
    PayloadTooLarge,
    InsufficientSolvers,
    PoolFull,
    NotFound,
    EncryptionFailed,
    DecryptionFailed,
    InvalidSignature,
    GossipError(GossipError),
}

#[derive(Debug)]
pub enum GossipError {
    NetworkError,
    InvalidMessage,
    ChannelClosed,
}

// Helper function for generating unique key IDs
fn generate_key_id() -> String {
    use rand::Rng;
    let mut rng = OsRng;
    format!("key-{}", rng.gen::<u64>())
}

// Helper function for getting current timestamp
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
