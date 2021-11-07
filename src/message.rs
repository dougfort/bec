use thiserror::Error;
use std::collections::HashSet;
use sha2::{Sha256, Digest};
use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::ed25519::signature::Signature;

#[derive(Error, Debug)]
pub enum MessageError {

    #[error("verify error")]
    VerifyError(#[from] ed25519_dalek::ed25519::Error)
}

// Message digest; cryptographic hash of (𝑣, hs, sig)
pub type MDigest = [u8; 32];

/// M is a set of triples (𝑣, hs, sig), where 𝑣 is any value, sig is a digital
/// signature over (𝑣, hs) using the sender’s private key, and hs is a
/// set of hashes produced by a cryptographic hash function 𝐻 (·).
pub struct Message {
    pub v: Vec::<u8>,
    pub hs: HashSet::<MDigest>,
    pub sig: [u8; 64],
}

impl Message {

    /// create a new message from its predecessor
    pub fn from_pred(
        pred: &Message,
        v: Vec::<u8>, 
        keypair: &ed25519_dalek::Keypair,
    ) -> Self {
        // hs for the new message is the the predecessor's hs plus
        // the predecessor's digest
        let mut hs = pred.hs.clone();
        let pred_digest = pred.digest();
        hs.insert(pred_digest);

        // sig is a digital signature over (𝑣, hs) using the sender’s private key
        let data = data_to_sign(&v, &hs);
        let sig = keypair.sign(&data).to_bytes();

        Message { v, hs, sig }
    }

    /// this is the root node, it has no predecessor
    pub fn is_root(&self) -> bool {
        self.hs.is_empty()
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
        // TODO: #1 cash digest value: it's not going to change
        let mut hasher  = Sha256::new();
        hasher.update(self.v.clone());
        for h in self.hs.iter() {
            hasher.update(h);
        }
        hasher.update(self.sig);

        // we use unwrap here because the hash is [u8, 32] just like MDigest
        hasher.finalize().as_slice().try_into().unwrap()
    }

    fn verify(&self, public_key: ed25519_dalek::PublicKey) -> Result<(), MessageError> {
        let data = data_to_sign(&self.v, &self.hs);
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig)?; 
        public_key.verify(&data, &sig)?;

        Ok(())
    }
}

fn data_to_sign(v: &[u8], hs: &HashSet::<MDigest>) -> Vec::<u8> {
    let mut data = Vec::<u8>::new();
    data.extend_from_slice(v);
    for h in hs.iter() {
        data.extend_from_slice(h);
    }
    data
}

/// This creates the root message
impl Default for Message {

    fn default() -> Self {
        Message{
            v: Vec::new(),
            hs: HashSet::new(),
            sig: [0; 64], 
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;   
    use crate::payload; 

    #[test]
    fn can_create_root() {
        let r: Message = Default::default();
        assert!(r.is_root())
    }

    #[test]
    fn can_create_message_from_predecessor() {
        let mut rand_generator = rand::rngs::OsRng {};

        let pred: Message = Default::default();
        let v = payload::generate(2048);
        let keypair = ed25519_dalek::Keypair::generate(&mut rand_generator);
    
        let m = Message::from_pred(&pred, v, &keypair);
        assert!(!m.is_root());

        assert!(pred.is_predecessor_of(&m));
        assert!(!pred.is_successor_of(&m));
        assert!(m.is_successor_of(&pred));
        assert!(!m.is_predecessor_of(&pred));

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
