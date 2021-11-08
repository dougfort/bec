use std::collections::HashMap;

pub type ReplicaId = usize;

pub struct Replica {
    pub id: ReplicaId,
    pub keypair: ed25519_dalek::Keypair,
    pub public_keys: HashMap::<ReplicaId, ed25519_dalek::PublicKey>,
}

/// Our system consists of a finite set of replicas, which may vary over time. 
/// Any replica may execute transactions.
/// they must all be created at once, so they know each other's public keys 
pub fn create_replicas(count: usize) -> Vec::<Replica> {
    let mut replicas: Vec::<Replica> = Vec::new();
    let mut public_keys = HashMap::new();

    for id in 1..=count {
        let replica = Replica {
            id, 
            keypair: create_random_keypair(),
            public_keys: HashMap::new(),
        };
        public_keys.insert(replica.id, replica.keypair.public);
        replicas.push(replica);
    }
    
    for replica in replicas.iter_mut() {
        replica.public_keys = public_keys.clone();
    }

    replicas
}

/// create a randomly generated ed25519_dalek::Keypair
pub fn create_random_keypair() -> ed25519_dalek::Keypair {
    let mut rand_generator = rand::rngs::OsRng {};
    ed25519_dalek::Keypair::generate(&mut rand_generator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_replicas() {
        let rs = create_replicas(0);
        assert!(rs.is_empty());

        let rs = create_replicas(1);
        assert_eq!(rs.len(), 1);

        let rs = create_replicas(2);
        assert_eq!(rs.len(), 2);

        assert!(rs[0].public_keys.get(&rs[1].id).is_some());
        assert!(rs[1].public_keys.get(&rs[0].id).is_some());
    }

}