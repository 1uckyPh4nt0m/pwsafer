use sha2::{Digest, Sha256};

use twofish::cipher::generic_array::typenum::U32;
use twofish::cipher::generic_array::GenericArray;

/// Returns ECB key generated from password using key stretching algorithm.
pub fn hash_password(salt: &[u8], iter: u32, password: &[u8]) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::default();
    hasher.update(password);
    hasher.update(&salt);
    let mut key = hasher.finalize();
    for _ in 0..iter {
        let mut hasher = Sha256::default();
        hasher.update(&key);
        key = hasher.finalize();
    }
    key
}
