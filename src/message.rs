use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("verify error")]
    VerifyError(#[from] ed25519_dalek::ed25519::Error),
}

/// create a randomly generated ed25519_dalek::Keypair
pub fn create_random_keypair() -> ed25519_dalek::Keypair {
    let mut rand_generator = rand::rngs::OsRng {};
    ed25519_dalek::Keypair::generate(&mut rand_generator)
}

// Message digest; cryptographic hash of (𝑣, hs, sig)
pub type MDigest = [u8; 32];

/// M is a set of triples (𝑣, hs, sig), where 𝑣 is any value, sig is a digital
/// signature over (𝑣, hs) using the sender’s private key, and hs is a
/// set of hashes produced by a cryptographic hash function 𝐻 (·).
#[derive(Debug, Clone)]
pub struct Message {
    pub v: Vec<u8>,
    pub hs: HashSet<MDigest>,
    pub sig: [u8; 64],
}

impl Message {
    /// create a new message as successor to the local heads
    pub fn from_heads(hs: HashSet<MDigest>, v: Vec<u8>, keypair: &ed25519_dalek::Keypair) -> Self {
        // sig is a digital signature over (𝑣, hs) using the sender’s private key
        let data = data_to_sign(&v, &hs);
        let sig = keypair.sign(&data).to_bytes();

        Message { v, hs, sig }
    }

    /// self is a predecessor of m if m.hs contains the digest of self
    pub fn is_predecessor_of(&self, m: &Message) -> bool {
        m.hs.get(&self.digest()).is_some()
    }

    /// self is successor of m if self.hs contains the digest of M
    pub fn is_successor_of(&self, m: &Message) -> bool {
        self.hs.get(&m.digest()).is_some()
    }

    /// compute the digest (cryptographic hash) of this nessage
    pub fn digest(&self) -> MDigest {
        // TODO: #1 cache digest value: it's not going to change
        let mut hasher = Sha256::new();
        hasher.update(self.v.clone());
        for h in self.hs.iter() {
            hasher.update(h);
        }
        hasher.update(self.sig);

        // we use unwrap here because the hash is [u8, 32] just like MDigest
        hasher.finalize().as_slice().try_into().unwrap()
    }

    pub fn verify(&self, public_key: ed25519_dalek::PublicKey) -> Result<(), MessageError> {
        let data = data_to_sign(&self.v, &self.hs);
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig)?;
        public_key.verify(&data, &sig)?;

        Ok(())
    }
}

fn data_to_sign(v: &[u8], hs: &HashSet<MDigest>) -> Vec<u8> {
    let mut data = Vec::<u8>::new();
    data.extend_from_slice(v);
    for h in hs.iter() {
        data.extend_from_slice(h);
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload;

    #[test]
    fn can_create_message_from_heads() {

        let hs = HashSet::new();
        let v = payload::generate(2048);
        let keypair = create_random_keypair();

        let m = Message::from_heads(hs, v, &keypair);

        // the message should be neither predecessor nor successor of itself
        assert!(!m.is_predecessor_of(&m));
        assert!(!m.is_successor_of(&m));

        assert!(m.verify(keypair.public).is_ok());

        // veify should fail if we change the data
        let mut m1 = m;
        m1.v[0] += 1;
        assert!(m1.verify(keypair.public).is_err());
    }
}
