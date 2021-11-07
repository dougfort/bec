/// Define a graph with a vertex for each message in M, and a
/// directed edge from each message to each of its predecessors. We
/// can assume that this graph is acyclic because the presence of a cycle
/// would imply knowledge of a collision in the hash function.[^Byzantine Eventual Consistency paper]

use std::collections::HashMap;
use crate::message::{MDigest, Message};

pub struct Node {
    pub msg: MDigest,
    pub preds: Vec::<MDigest>,
}

pub struct Graph {
    pub heads: Vec::<MDigest>,
    pub root: Node,
    pub repo: HashMap::<MDigest, Message>,
}

impl Graph {

    pub fn new() -> Self {
        let root: Message = Default::default();
        let root_node = Node{ msg: root.digest(), preds: Vec::new()};
        let mut g = Graph{
            heads: Vec::new(),
            root: root_node,
            repo: HashMap::<MDigest, Message>::new(),
        };
        g.heads.push(root.digest());
        g.repo.insert(root.digest(), root);

        g
    }
}

/// This creates an "empty" graph - only root defined
impl Default for Graph {

    fn default() -> Self {
        Graph::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;   
    use crate::payload; 

    #[test]
    fn can_create_empty_graph() {
        let g: Graph = Default::default();
        assert_eq!(g.heads.len(), 1);
        assert_eq!(g.heads[0], g.root.msg);
        assert_eq!(g.repo.len(), 1);
        assert!(g.repo.get(&g.root.msg).is_some());
    }
}
