use near_sdk::{AccountId, CryptoHash, env};

// Used to generate a unique prefix in our storage collections to avoid any collisions.
pub(crate) fn hash_account_id(account_id: &AccountId) -> CryptoHash {
    let mut hash = CryptoHash::default();
    hash.copy_from_slice(&env::sha256(account_id.as_bytes()));
    hash
}
