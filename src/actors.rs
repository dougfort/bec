use std::collections::HashMap;

pub type ActorId = usize;

pub struct Actor {
    pub id: ActorId,
    pub keypair: ed25519_dalek::Keypair,
    pub public_keys: HashMap::<ActorId, ed25519_dalek::PublicKey>,
}
