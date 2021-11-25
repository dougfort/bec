use anyhow::Result;

mod connection;
mod message;
mod payload;
mod repo;
mod replica;

use message::{Message, MDigest};

fn main() -> Result<()> {

    // p
    //
    //         <- C <- D <- E
    // A <- B               |    
    //         <- J  <----- |
    //               <- K <- L <- M

    let mut mr = repo::MessageRepo::new();
    let keypair = replica::create_random_keypair();

    let label = "A".to_string();
    let m = Message::new(
        vec![], 
        payload::generate(2048), 
        Some(label.clone()), 
        &keypair,
    );
    let a_d = m.digest();
    mr.insert_message(m).unwrap();

    let label = "B".to_string();
    let m = Message::new(
        vec![a_d], 
        payload::generate(2048), 
        Some(label.clone()), 
        &keypair,
    );
    let b_d = m.digest();
    mr.insert_message(m).unwrap();

    let label = "C".to_string();
    let m = Message::new(
        vec![b_d], 
        payload::generate(2048), 
        Some(label.clone()), 
        &keypair,
    );
    let c_d = m.digest();
    mr.insert_message(m).unwrap();

    let label = "D".to_string();
    let m = Message::new(
        vec![c_d], 
        payload::generate(2048), 
        Some(label.clone()), 
        &keypair,
    );
    mr.insert_message(m).unwrap();

    let label = "J".to_string();
    let m = Message::new(
        vec![b_d], 
        payload::generate(2048), 
        Some(label.clone()), 
        &keypair,
    );
    mr.insert_message(m).unwrap();

    dump_mr(&mr);

    Ok(())
}

pub fn dump_mr(mr: &repo::MessageRepo) {
    for head in &mr.heads {
        println!("{}", get_label(mr, head));
        let indent = 4;
        let edges = mr.edges.get(head).unwrap();
        dump_edges(mr, edges, indent);
    }
}

fn dump_edges(mr: &repo::MessageRepo, edges: &[MDigest], indent: usize) {
    for edge in edges {
        println!("{:width$}{}", " ", get_label(mr, edge), width=indent);
        if let Some(preds) = mr.edges.get(edge) {
            dump_edges(mr, preds, indent+4);
        }
    }
}

fn get_label(mr: &repo::MessageRepo, d: &MDigest) -> String {
    match mr.messages.get(d) {
        Some(msg) => {
            match &msg.label {
                Some(label) => label.to_string(),
                None => "?".to_string()
            }
        }
        None => "?".to_string()
    }
}
