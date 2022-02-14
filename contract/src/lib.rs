use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, LookupSet};
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
    site_password_id_by_account: LookupMap<AccountId, LookupSet<PassId>>,
    /// Collection of all the encrypted passwords by their Ids.
    site_password: LookupMap<PassId, EncryptedSitePassword>,
    /// Hashes of the accounts to verify what master password they used to encrypt
    /// site passwords.
    account_hash: LookupMap<AccountId, String>,
}

/// Helper structure for keys of the persistent collections.
#[derive(BorshSerialize)]
pub enum StorageKey {
    SitePasswordIdByAccount,
    SitePasswordIdByAccountInner { account_id_hash: CryptoHash },
    SitePassword,
    AccountHash,
}

impl Default for NearPass {
    fn default() -> Self {
        Self {
            current_pass_id: 0,
            site_password_id_by_account: LookupMap::new(
                StorageKey::SitePasswordIdByAccount.try_to_vec().unwrap(),
            ),
            site_password: LookupMap::new(StorageKey::SitePassword.try_to_vec().unwrap()),
            account_hash: LookupMap::new(StorageKey::AccountHash.try_to_vec().unwrap()),
        }
    }
}

#[near_bindgen]
impl NearPass {
    /// Initializes the account hash for the very first time. Does not update once initialized.
    pub fn initialize_account_hash(&mut self, hash: String) {
        let account_id = env::signer_account_id();
        let saved_hash = self.account_hash.get(&account_id);
        assert!(saved_hash.is_none(), "Cannot re-initialize account hash");
        self.account_hash.insert(&account_id, &hash);
    }

    /// Gets the hash for the account.
    pub fn get_account_hash(&self) -> String {
        let account_id = env::signer_account_id();
        let hash = self.account_hash.get(&account_id);
        assert!(hash.is_some(), "Account hash not initialized yet");
        hash.unwrap()
    }

    /// Add a site password for the account.
    pub fn add_site_password(&mut self, enc_pass: EncryptedSitePassword) -> PassId {
        let account_id = env::signer_account_id();
        env::log(format!("Add a site password for account '{}'", account_id).as_bytes());

        let cur_pass_id = self.current_pass_id;
        self.current_pass_id += 1;

        // Add the site password.
        self.site_password.insert(&cur_pass_id, &enc_pass);

        let mut account_site_passes = self.site_password_id_by_account.get(&account_id);

        // If the account id is not present, create one.
        if account_site_passes.is_none() {
            account_site_passes = Option::Some(LookupSet::new(
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

        return cur_pass_id;
    }

    /// Panics if the site password is not owned by the account.
    /// Returns account if it is needed by the caller.
    fn panic_if_site_password_not_owner(
        &self,
        account_id: &AccountId,
        pass_id: PassId,
    ) -> LookupSet<PassId> {
        let account = self.site_password_id_by_account.get(&account_id);
        // The error will just respond with a typical 404 error to obfuscate if an account exists
        // or it owns the password.
        assert!(account.is_some(), "No site password found");

        let account = account.unwrap();
        assert!(account.contains(&pass_id), "No site password found");

        account
    }

    /// Gets the site password for the account referenced by the pass id.
    pub fn get_site_password(&self, pass_id: PassId) -> EncryptedSitePassword {
        let account_id = env::signer_account_id();
        self.panic_if_site_password_not_owner(&account_id, pass_id);

        let site_pass = self.site_password.get(&pass_id);
        assert!(site_pass.is_some(), "No site password found");

        site_pass.unwrap()
    }

    /// Updates the pre-existing site password.
    pub fn update_site_password(&mut self, pass_id: PassId, enc_pass: EncryptedSitePassword) {
        let account_id = env::signer_account_id();
        self.panic_if_site_password_not_owner(&account_id, pass_id);

        // Overwrite the pre-existing site password.
        self.site_password.insert(&pass_id, &enc_pass);
    }

    /// Deletes a site password if it exists.
    pub fn delete_site_password(&mut self, pass_id: PassId) {
        let account_id = env::signer_account_id();
        let mut account = self.panic_if_site_password_not_owner(&account_id, pass_id);

        // Remove the password from the account.
        account.remove(&pass_id);

        // Remove from storage as well.
        self.site_password.remove(&pass_id);
    }

    /// Gets all the password ids for a given account.
    pub fn get_all_site_password_ids(&self) -> Option<LookupSet<PassId>> {
        let account_id = env::signer_account_id();
        self.site_password_id_by_account.get(&account_id)
    }

    /// Gets all the encrypted passwords for the given ids for an account.
    pub fn get_site_passwords_by_ids(&self, pass_ids: Vec<PassId>) -> Vec<EncryptedSitePassword> {
        let account_id = env::signer_account_id();

        let account = self.site_password_id_by_account.get(&account_id);
        assert!(account.is_some(), "No site password found");
        let account = account.unwrap();

        // Check if all the pass_ids that are sent in the request are owned by the account.
        let all_owned = pass_ids.iter().all(|it| account.contains(it));
        assert!(all_owned, "No site password found");

        pass_ids
            .iter()
            .map(|it| self.site_password.get(it).unwrap())
            .collect()
    }
}

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
    fn add_site_password() {
        let context = get_context(vec![], false);
        testing_env!(context);

        let mut contract = NearPass::default();
        let pass_id = contract.add_site_password("encrypted_pass".to_string());

        let encrypted_pass = contract.get_site_password(pass_id);
        assert_eq!(encrypted_pass, "encrypted_pass");
    }

    #[test]
    fn update_site_password() {
        let context = get_context(vec![], false);
        testing_env!(context);

        let mut contract = NearPass::default();
        let pass_id = contract.add_site_password("encrypted_pass".to_string());

        let encrypted_pass = contract.get_site_password(pass_id);
        assert_eq!(encrypted_pass, "encrypted_pass");

        // Update the password.
        contract.update_site_password(pass_id, "new_encrypted_pass".to_string());

        let new_enc_pass = contract.get_site_password(pass_id);
        assert_eq!(new_enc_pass, "new_encrypted_pass");
    }

    #[test]
    #[should_panic(expected = "No site password found")]
    fn delete_site_password() {
        let context = get_context(vec![], false);
        testing_env!(context);

        let mut contract = NearPass::default();
        let pass_id = contract.add_site_password("encrypted_pass".to_string());

        let encrypted_pass = contract.get_site_password(pass_id);
        assert_eq!(encrypted_pass, "encrypted_pass");

        // Delete the password.
        contract.delete_site_password(pass_id);

        // Check if it is deleted.
        contract.get_site_password(pass_id);
    }

    #[test]
    fn get_all_site_password_ids() {
        let context = get_context(vec![], false);
        testing_env!(context);

        let mut contract = NearPass::default();
        contract.add_site_password("encrypted_pass".to_string());
        contract.add_site_password("new_encrypted_pass".to_string());

        let all_password_ids = contract.get_all_site_password_ids();
        assert!(all_password_ids.is_some());
        let all_password_ids = all_password_ids.unwrap();
        assert!(all_password_ids.contains(&0));
        assert!(all_password_ids.contains(&1));
        assert!(!all_password_ids.contains(&2));
    }

    #[test]
    fn get_site_passwords_by_ids() {
        let context = get_context(vec![], false);
        testing_env!(context);

        let mut contract = NearPass::default();
        contract.add_site_password("encrypted_pass".to_string());
        contract.add_site_password("new_encrypted_pass".to_string());

        let enc_passes = contract.get_site_passwords_by_ids(vec![0, 1]);
        assert_eq!(enc_passes, vec!["encrypted_pass", "new_encrypted_pass"]);
    }
}
