use crate::message::{MDigest, Message};
use std::collections::{HashMap, HashSet};

pub struct MessageRepo {
    heads: HashSet<MDigest>,

    messages: HashMap<MDigest, Message>,
}

impl MessageRepo {
    pub fn new() -> Self {
        MessageRepo {
            heads: HashSet::new(),
            messages: HashMap::new(),
        }
    }

    pub fn create_message(&mut self, data: Vec<u8>, keypair: &ed25519_dalek::Keypair) -> MDigest {
        let m = Message::from_heads(self.heads.clone(), data, keypair);
        let digest = m.digest();

        self.heads.clear();
        self.heads.insert(digest);
        self.messages.insert(digest, m);

        digest
    }

    pub fn get_message(&self, digest: MDigest) -> Option<&Message> {
        self.messages.get(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica;
    use crate::payload;

    #[test]
    fn can_create_repo() {
        MessageRepo::new();
    }

    #[test]
    fn can_create_messages() {
        let mut mr = MessageRepo::new();

        let keypair = replica::create_random_keypair();

        let m1data = payload::generate(2048);
        let m1d = mr.create_message(m1data, &keypair);
        let m1 = mr.get_message(m1d).unwrap().clone();
        assert!(m1.verify(keypair.public).is_ok());

        let m2data = payload::generate(2048);
        let m2d = mr.create_message(m2data, &keypair);
        let m2 = mr.get_message(m2d).unwrap().clone();
        assert!(m2.verify(keypair.public).is_ok());

        assert!(m1.is_predecessor_of(&m2));
        assert!(m2.is_successor_of(&m1)); 
    }
}
