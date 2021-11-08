use std::collections::HashMap;

pub type ActorId = usize;

pub struct Actor {
    pub id: ActorId,
    pub keypair: ed25519_dalek::Keypair,
    pub public_keys: HashMap::<ActorId, ed25519_dalek::PublicKey>,
}

/// create a group of actors
/// they must all be created at once, so they know each other's public keys 
pub fn create_actors(count: usize) -> Vec::<Actor> {
    let mut actors: Vec::<Actor> = Vec::new();
    let mut public_keys = HashMap::new();

    for id in 1..=count {
        let actor = Actor {
            id, 
            keypair: create_random_keypair(),
            public_keys: HashMap::new(),
        };
        public_keys.insert(actor.id, actor.keypair.public);
    }
    
    for actor in actors.iter_mut() {
        actor.public_keys = public_keys.clone();
    }

    actors
}

/// create a randomly generated ed25519_dalek::Keypair
pub fn create_random_keypair() -> ed25519_dalek::Keypair {
    let mut rand_generator = rand::rngs::OsRng {};
    ed25519_dalek::Keypair::generate(&mut rand_generator)
}

