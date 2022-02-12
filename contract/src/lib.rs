use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};
use near_sdk::{env, near_bindgen, setup_alloc, AccountId, CryptoHash};

mod hash;

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

/// Helper structure for keys of the persistent collections.
#[derive(BorshSerialize)]
pub enum StorageKey {
    SitePasswordIdByAccount,
    SitePasswordIdByAccountInner { account_id_hash: CryptoHash },
    SitePassword,
}

impl Default for NearPass {
    fn default() -> Self {
        Self {
            current_pass_id: 0,
            site_password_id_by_account: LookupMap::new(
                StorageKey::SitePasswordIdByAccount.try_to_vec().unwrap(),
            ),
            site_password: LookupMap::new(StorageKey::SitePassword.try_to_vec().unwrap()),
        }
    }
}

#[near_bindgen]
impl NearPass {
    /// Add a site password for the account.
    pub fn add_site_password(&mut self, enc_pass: EncryptedSitePassword) {
        let account_id = env::signer_account_id();
        env::log(format!("Add a site password for account '{}'", account_id).as_bytes());

        let cur_pass_id = self.current_pass_id;
        self.current_pass_id += 1;

        // Add the site password.
        self.site_password.insert(&cur_pass_id, &enc_pass);

        let mut account_site_passes = self.site_password_id_by_account.get(&account_id);

        // If the account id is not present, create one.
        if account_site_passes.is_none() {
            account_site_passes = Option::Some(UnorderedSet::new(
                StorageKey::SitePasswordIdByAccountInner {
                    account_id_hash: hash::hash_account_id(&account_id),
                }
                .try_to_vec()
                .unwrap(),
            ));
            self.site_password_id_by_account
                .insert(&account_id, account_site_passes.as_ref().unwrap());
        }

        // Record the new site password for the account.
        let mut account_site_passes = account_site_passes.unwrap();
        account_site_passes.insert(&cur_pass_id);
    }

    /// Gets the site password for the account referenced by the pass id.
    pub fn get_site_password(&self, pass_id: PassId) -> EncryptedSitePassword {
        let account_id = env::signer_account_id();

        let account = self.site_password_id_by_account.get(&account_id);
        assert!(account.is_some(), "No site password found");

        let account = account.unwrap();
        assert!(account.contains(&pass_id), "No site password found");

        let site_pass = self.site_password.get(&pass_id);
        assert!(site_pass.is_some(), "No site password found");

        site_pass.unwrap()
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
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};

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
        contract.add_site_password("encrypted_pass".to_string());
    }
}
