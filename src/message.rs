use ed25519_dalek::ed25519::signature::Signature;
use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageError {
    #[error("verify error")]
    Verify(#[from] ed25519_dalek::ed25519::Error),
}

// Message digest; cryptographic hash of (𝑣, hs, sig)
pub type MDigest = [u8; 32];

/// Message represents a triple (𝑣, hs, sig)
#[derive(Debug, Clone)]
pub struct Message {

    /// 𝑣 is any value
    pub v: Vec<u8>,

    /// hs is heads(M) denoting the set of hashes of those messages in M
    /// that have no successors
    pub hs: HashSet<MDigest>,

    /// sig is a digital signature over (𝑣, hs) using the sender’s private key
    pub sig: [u8; 64],

    /// label is an optional tag that makes it easier to identify the message
    /// particularly to label nodes in graphs such as Figure 5
    pub label: Option<String>,
}

impl Message {
    /// create a new message as successor to the local heads
    pub fn new(
        heads: Vec<MDigest>, 
        v: Vec<u8>, 
        label: Option<String>,
        keypair: &ed25519_dalek::Keypair,
    ) -> Self {

        let mut hs: HashSet<MDigest> = HashSet::new();
        for head in heads {
            hs.insert(head);
        }
        // sig is a digital signature over (𝑣, hs) using the sender’s private key
        let data = data_to_sign(&v, &hs);
        let sig = keypair.sign(&data).to_bytes();

        Message { v, hs, sig, label }
    }

    /// self is successor of m if self.hs contains the digest of M
    pub fn is_successor_of(&self, d: &MDigest) -> bool {
        self.hs.get(d).is_some()
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
    use crate::replica;
    use crate::payload;

    #[test]
    fn can_create_message_new() {

        let heads = Vec::new();
        let v = payload::generate(2048);
        let keypair = replica::create_random_keypair();

        let m = Message::new(heads, v, None, &keypair);

        // the message should be neither predecessor nor successor of itself
        assert!(!m.is_successor_of(&m.digest()));

        assert!(m.verify(keypair.public).is_ok());

        // veify should fail if we change the data
        let mut m1 = m;
        m1.v[0] += 1;
        assert!(m1.verify(keypair.public).is_err());
    }
}
