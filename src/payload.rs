use rand::Rng;

/// generate a random payload for testing, under max size
pub fn generate(max: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let size: usize = rng.gen();
    let size = size % max;
    rng.sample_iter(rand::distributions::Standard)
        .take(size)
        .collect()
}
