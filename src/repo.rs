use crate::message::{MDigest, Message};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RepoError {
    #[error("duplicate message: {0:?}")]
    Message(MDigest),
    #[error("duplicate edges: {0:?}")]
    Edges(MDigest),
    #[error("duplicate label: '{0}'")]
    Label(String),
}

pub struct MessageRepo {
    pub heads: HashSet<MDigest>,

    pub messages: HashMap<MDigest, Message>,
    pub edges: HashMap<MDigest, Vec<MDigest>>,
    pub labels: HashMap<String, MDigest>,
}

impl MessageRepo {
    pub fn new() -> Self {
        MessageRepo {
            heads: HashSet::new(),
            messages: HashMap::new(),
            edges: HashMap::new(),
            labels: HashMap::new(),
        }
    }
        
    // reconcile our repository with some other repository
    // return a new, combined repository
    pub fn reconcile(&self, other: &MessageRepo) -> Self {
        let mut mr = Default::default();

        mr
    }

    pub fn insert_message(&mut self, m: Message) -> Result<(), RepoError> {
        let d = m.digest();
        if self.messages.contains_key(&d) {
            return Err(RepoError::Message(d));
        }
        if self.edges.contains_key(&d) {
            return Err(RepoError::Edges(d));
        }
        let l = m.label.clone();
        if let Some(label) = l {
            if self.labels.contains_key(&label) {
                return Err(RepoError::Label(label));
            }
            self.labels.insert(label, d);    
        }

        let mut preds: Vec<MDigest> = Vec::new();
        for head in self.heads.iter() {
            if m.is_successor_of(head) {
                preds.push(*head)
            }
        } 
        // if this message is a successor of one of the heads, remove that head
        // this message becomes a new head
        for pred in preds.iter() {
            self.heads.remove(pred);
        }
        self.heads.insert(d);

        self.messages.insert(d, m);
        self.edges.insert(d, preds);

        Ok(())
    }

    pub fn replace_heads(&mut self, ds: Vec<MDigest>) {
        self.heads.clear();
        for d in ds {
            self.heads.insert(d);    
        }
    }

    pub fn get_message(&self, digest: &MDigest) -> Option<&Message> {
        self.messages.get(digest)
    }

    pub fn get_digest(&self, label: &str) -> Option<&MDigest> {
        self.labels.get(label)
    }

}

impl Default for MessageRepo {
    fn default() -> Self {
        MessageRepo {
            heads: HashSet::new(),
            messages: HashMap::new(),
            edges: HashMap::new(),
            labels: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replica;
    use crate::payload;

    #[test]
    fn can_reconcile_empty_repo() {
        let mr1 = MessageRepo::new();
        let mr2 = MessageRepo::new();
        let mr3 = mr1.reconcile(&mr2);
        assert!(mr3.heads.is_empty());
        assert!(mr3.messages.is_empty());
        assert!(mr3.edges.is_empty());
        assert!(mr3.labels.is_empty());
    }

    #[test]
    fn can_create_messages() {
        let mut mr = MessageRepo::new();

        let keypair = replica::create_random_keypair();

        let m1data = payload::generate(2048);
        let m = Message::new(vec![], m1data, Some("m1".to_string()), &keypair);
        let m1d = m.digest();
        mr.insert_message(m).unwrap();
        let m1 = mr.get_message(&m1d).unwrap().clone();
        assert!(m1.verify(keypair.public).is_ok());

        let m2data = payload::generate(2048);
        let m = Message::new(vec![m1d], m2data, Some("m2".to_string()), &keypair);
        let m2d = m.digest();
        mr.insert_message(m).unwrap();
        let m2 = mr.get_message(&m2d).unwrap().clone();
        assert!(m2.verify(keypair.public).is_ok());

        assert!(m2.is_successor_of(&m1d)); 

        match mr.get_digest("m1") {
            Some(digest) => assert_eq!(*digest, m1d),
            None => panic!("unable to find digest"),
        }

        match mr.get_digest("m2") {
            Some(digest) => assert_eq!(*digest, m2d),
            None => panic!("unable to find digest"),
        }
    }
}
