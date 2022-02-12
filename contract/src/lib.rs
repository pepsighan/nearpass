use near_sdk::{AccountId, env, near_bindgen, setup_alloc};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};

setup_alloc!();

/// ID for the Site Password.
pub type PassId = u64;

/// EncryptedSitePassword is a tuple of Site, Username and Password that is encrypted using
/// the user's private key. So, nobody is the world except the user itself can view what is stored
/// in the text.
pub type EncryptedSitePassword = String;

/// NearPass stores the
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct NearPass {
    /// Counter for the password id.
    current_pass_id: PassId,
    /// Collection of all password Ids for each account.
    site_password_id_by_account: LookupMap<AccountId, UnorderedSet<PassId>>,
    /// Collection of all the encrypted passwords by their Ids.
    site_password: LookupMap<PassId, EncryptedSitePassword>,
}

impl Default for NearPass {
    fn default() -> Self {
        Self {
            current_pass_id: 0,
            site_password_id_by_account: LookupMap::new(b"a".to_vec())
            site_password: LookupMap::new(b"b".to_vec()),
        }
    }
}

#[near_bindgen]
impl NearPass {
    pub fn set_greeting(&mut self, message: String) {
        let account_id = env::signer_account_id();

        // Use env::log to record logs permanently to the blockchain!
        env::log(format!("Saving greeting '{}' for account '{}'", message, account_id, ).as_bytes());

        self.password_map.insert(&account_id, &message);
    }

    // `match` is similar to `switch` in other languages; here we use it to default to "Hello" if
    // self.records.get(&account_id) is not yet defined.
    // Learn more: https://doc.rust-lang.org/book/ch06-02-match.html#matching-with-optiont
    pub fn get_greeting(&self, account_id: String) -> String {
        match self.password_map.get(&account_id) {
            Some(greeting) => greeting,
            None => "Hello".to_string(),
        }
    }
}

/*
 * The rest of this file holds the inline tests for the code above
 * Learn more about Rust tests: https://doc.rust-lang.org/book/ch11-01-writing-tests.html
 *
 * To run from contract directory:
 * cargo test -- --nocapture
 *
 * From project root, to run in combination with frontend tests:
 * yarn test
 *
 */
#[cfg(test)]
mod tests {
    use near_sdk::{testing_env, VMContext};
    use near_sdk::MockedBlockchain;

    use super::*;

    // mock the context for testing, notice "signer_account_id" that was accessed above from env::
    fn get_context(input: Vec<u8>, is_view: bool) -> VMContext {
        VMContext {
            current_account_id: "alice_near".to_string(),
            signer_account_id: "bob_near".to_string(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id: "carol_near".to_string(),
            input,
            block_index: 0,
            block_timestamp: 0,
            account_balance: 0,
            account_locked_balance: 0,
            storage_usage: 0,
            attached_deposit: 0,
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view,
            output_data_receivers: vec![],
            epoch_height: 19,
        }
    }

    #[test]
    fn set_then_get_greeting() {
        let context = get_context(vec![], false);
        testing_env!(context);
        let mut contract = NearPass::default();
        contract.set_greeting("howdy".to_string());
        assert_eq!(
            "howdy".to_string(),
            contract.get_greeting("bob_near".to_string())
        );
    }

    #[test]
    fn get_default_greeting() {
        let context = get_context(vec![], true);
        testing_env!(context);
        let contract = NearPass::default();
        // this test did not call set_greeting so should return the default "Hello" greeting
        assert_eq!(
            "Hello".to_string(),
            contract.get_greeting("francis.near".to_string())
        );
    }
}
