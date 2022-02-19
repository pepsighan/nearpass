use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedSet};
use near_sdk::{env, near_bindgen, setup_alloc, AccountId, CryptoHash};

mod hash;

setup_alloc!();

/// ID for the data.
pub type DataId = u64;

/// EncryptedData is a text that is encrypted using the user's encryption key. So, nobody is
/// the world except the user itself can view what is stored in the text.
pub type EncryptedData = String;

/// NearPass stores the
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct NearPass {
    /// Counter for the data id.
    current_data_id: DataId,
    /// Collection of all password ids for each account.
    site_password_id_by_account: LookupMap<AccountId, UnorderedSet<DataId>>,
    /// Collection of all text data ids for each account.
    text_id_by_account: LookupMap<AccountId, UnorderedSet<DataId>>,
    /// Collection of all the encrypted data by their ids.
    data_map: LookupMap<DataId, EncryptedData>,
    /// Signatures of the accounts to verify to verify if an encryption key is associated with an
    /// account.
    account_signature: LookupMap<AccountId, String>,
}

/// Helper structure for keys of the persistent collections.
#[derive(BorshSerialize)]
pub enum StorageKey {
    SitePasswordIdByAccount,
    SitePasswordIdByAccountInner { account_id_hash: CryptoHash },
    TextIdByAccount,
    TextIdByAccountInner { account_id_hash: CryptoHash },
    DataMap,
    AccountSignature,
}

impl Default for NearPass {
    fn default() -> Self {
        Self {
            current_data_id: 0,
            site_password_id_by_account: LookupMap::new(
                StorageKey::SitePasswordIdByAccount.try_to_vec().unwrap(),
            ),
            text_id_by_account: LookupMap::new(StorageKey::TextIdByAccount.try_to_vec().unwrap()),
            data_map: LookupMap::new(StorageKey::DataMap.try_to_vec().unwrap()),
            account_signature: LookupMap::new(StorageKey::AccountSignature.try_to_vec().unwrap()),
        }
    }
}

#[near_bindgen]
impl NearPass {
    /// Initializes the account signature for the very first time.
    pub fn initialize_account_signature(&mut self, signature: String) {
        let account_id = env::signer_account_id();
        let saved_hash = self.account_signature.get(&account_id);
        assert!(
            saved_hash.is_none(),
            "NearpassAlreadyInitialized: Cannot re-initialize account signature"
        );
        self.account_signature.insert(&account_id, &signature);
    }

    /// Gets the signature for the account.
    pub fn get_account_signature(&self, account_id: String) -> String {
        let hash = self.account_signature.get(&account_id);
        assert!(
            hash.is_some(),
            "NearpassAccountNotInitialized: Account signature not initialized yet"
        );
        hash.unwrap()
    }

    /// Add a site password for the account.
    pub fn add_site_password(&mut self, enc_pass: EncryptedData) -> DataId {
        let account_id = env::signer_account_id();
        env::log(format!("Add a site password for account '{}'", account_id).as_bytes());

        let cur_data_id = self.current_data_id;
        self.current_data_id += 1;

        // Add the site password.
        self.data_map.insert(&cur_data_id, &enc_pass);

        let mut acc_pass_ids = self.site_password_id_by_account.get(&account_id);

        // If the account id is not present, create one.
        if acc_pass_ids.is_none() {
            acc_pass_ids = Option::Some(UnorderedSet::new(
                StorageKey::SitePasswordIdByAccountInner {
                    account_id_hash: hash::hash_account_id(&account_id),
                }
                .try_to_vec()
                .unwrap(),
            ));
        }

        // Record the new site password for the account.
        let mut acc_pass_ids = acc_pass_ids.unwrap();
        acc_pass_ids.insert(&cur_data_id);
        self.site_password_id_by_account
            .insert(&account_id, &acc_pass_ids);

        return cur_data_id;
    }

    /// Panics if the site password is not owned by the account.
    fn panic_if_account_invalid_for_site_password(
        &self,
        account_id: &AccountId,
        pass_id: DataId,
    ) -> UnorderedSet<DataId> {
        let account = self.site_password_id_by_account.get(&account_id);
        // The error will just respond with a typical 404 error to obfuscate if an account exists
        // or it owns the password.
        assert!(
            account.is_some(),
            "NearpassNoSitePass: No site password found"
        );

        let account = account.unwrap();
        assert!(
            account.contains(&pass_id),
            "NearpassNoSitePass: No site password found"
        );

        account
    }

    /// Gets the site password for the account referenced by the pass id.
    pub fn get_site_password(&self, account_id: String, pass_id: DataId) -> EncryptedData {
        self.panic_if_account_invalid_for_site_password(&account_id, pass_id);

        let site_pass = self.data_map.get(&pass_id);
        assert!(
            site_pass.is_some(),
            "NearpassNoSitePass: No site password found"
        );

        site_pass.unwrap()
    }

    /// Updates the pre-existing site password.
    pub fn update_site_password(&mut self, pass_id: DataId, enc_pass: EncryptedData) {
        let account_id = env::signer_account_id();
        self.panic_if_account_invalid_for_site_password(&account_id, pass_id);

        // Overwrite the pre-existing site password.
        self.data_map.insert(&pass_id, &enc_pass);
    }

    /// Deletes a site password if it exists.
    pub fn delete_site_password(&mut self, pass_id: DataId) {
        let account_id = env::signer_account_id();
        let mut account = self.panic_if_account_invalid_for_site_password(&account_id, pass_id);

        // Remove the password from the account.
        account.remove(&pass_id);

        // Remove from storage as well.
        self.data_map.remove(&pass_id);
    }

    /// Gets all the password ids for a given account.
    pub fn get_all_site_password_ids(&self, account_id: String) -> Option<Vec<DataId>> {
        let pass_ids = self.site_password_id_by_account.get(&account_id)?;
        Some(pass_ids.to_vec())
    }

    /// Gets all the encrypted passwords for the given ids for an account.
    pub fn get_site_passwords_by_ids(
        &self,
        account_id: String,
        pass_ids: Vec<DataId>,
    ) -> Vec<EncryptedData> {
        let account = self.site_password_id_by_account.get(&account_id);
        assert!(
            account.is_some(),
            "NearpassNoSitePass: No site password found"
        );
        let account = account.unwrap();

        // Check if all the pass_ids that are sent in the request are owned by the account.
        let all_owned = pass_ids.iter().all(|it| account.contains(it));
        assert!(all_owned, "NearpassNoSitePass: No site password found");

        pass_ids
            .iter()
            .map(|it| self.data_map.get(it).unwrap())
            .collect()
    }

    /// Add a text for the account.
    pub fn add_text(&mut self, enc_text: EncryptedData) -> DataId {
        let account_id = env::signer_account_id();
        env::log(format!("Add a text for account '{}'", account_id).as_bytes());

        let cur_data_id = self.current_data_id;
        self.current_data_id += 1;

        // Add the text.
        self.data_map.insert(&cur_data_id, &enc_text);

        let mut acc_text_ids = self.text_id_by_account.get(&account_id);

        // If the account id is not present, create one.
        if acc_text_ids.is_none() {
            acc_text_ids = Option::Some(UnorderedSet::new(
                StorageKey::TextIdByAccountInner {
                    account_id_hash: hash::hash_account_id(&account_id),
                }
                .try_to_vec()
                .unwrap(),
            ));
        }

        // Record a new text for the account.
        let mut acc_text_ids = acc_text_ids.unwrap();
        acc_text_ids.insert(&cur_data_id);
        self.text_id_by_account.insert(&account_id, &acc_text_ids);

        return cur_data_id;
    }

    /// Panics if the text not owned by the account.
    fn panic_if_account_invalid_for_text(
        &self,
        account_id: &AccountId,
        text_id: DataId,
    ) -> UnorderedSet<DataId> {
        let account = self.text_id_by_account.get(&account_id);
        assert!(account.is_some(), "NearpassNoText: No text found");

        let account = account.unwrap();
        assert!(account.contains(&text_id), "NearpassNoText: No text found");

        account
    }

    /// Gets the text for the account referenced by the text id.
    pub fn get_text(&self, account_id: String, text_id: DataId) -> EncryptedData {
        self.panic_if_account_invalid_for_text(&account_id, text_id);

        let text = self.data_map.get(&text_id);
        assert!(text.is_some(), "NearpassNoText: No text found");

        text.unwrap()
    }

    /// Updates the pre-existing text for the account.
    pub fn update_text(&mut self, text_id: DataId, enc_text: EncryptedData) {
        let account_id = env::signer_account_id();
        self.panic_if_account_invalid_for_text(&account_id, text_id);

        // Overwrite the pre-existing text.
        self.data_map.insert(&text_id, &enc_text);
    }

    /// Deletes a text if it exists.
    pub fn delete_text(&mut self, text_id: DataId) {
        let account_id = env::signer_account_id();
        let mut account = self.panic_if_account_invalid_for_text(&account_id, text_id);

        // Remove the text from the account.
        account.remove(&text_id);

        // Remove from storage as well.
        self.data_map.remove(&text_id);
    }

    /// Gets all the text ids for a given account.
    pub fn get_all_text_ids(&self, account_id: String) -> Option<Vec<DataId>> {
        let text_ids = self.text_id_by_account.get(&account_id)?;
        Some(text_ids.to_vec())
    }

    /// Gets all the text for the given ids for an account.
    pub fn get_texts_by_ids(
        &self,
        account_id: String,
        text_ids: Vec<DataId>,
    ) -> Vec<EncryptedData> {
        let account = self.text_id_by_account.get(&account_id);
        assert!(account.is_some(), "NearpassNoText: No text found");
        let account = account.unwrap();

        // Check if all the text ids that are sent in the request are owned by the account.
        let all_owned = text_ids.iter().all(|it| account.contains(it));
        assert!(all_owned, "NearpassNoText: No text found");

        text_ids
            .iter()
            .map(|it| self.data_map.get(it).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};

    use super::*;

    // mock the context for testing, notice "signer_account_id" that was accessed above from env::
    pub fn get_context(input: Vec<u8>, is_view: bool) -> VMContext {
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
    fn initialize_account_hash() {
        let context = get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        contract.initialize_account_signature("sign".to_string());
        let sign = contract.get_account_signature(accound_id);
        assert_eq!(sign, "sign");
    }

    #[test]
    #[should_panic(
        expected = "NearpassAccountNotInitialized: Account signature not initialized yet"
    )]
    fn get_account_hash_for_nonexistent_account() {
        let context = get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let contract = NearPass::default();
        contract.get_account_signature(accound_id);
    }

    #[test]
    fn add_site_password() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        let pass_id = contract.add_site_password("encrypted_pass".to_string());

        let encrypted_pass = contract.get_site_password(accound_id, pass_id);
        assert_eq!(encrypted_pass, "encrypted_pass");
    }

    #[test]
    fn update_site_password() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        let pass_id = contract.add_site_password("encrypted_pass".to_string());

        let encrypted_pass = contract.get_site_password(accound_id.clone(), pass_id);
        assert_eq!(encrypted_pass, "encrypted_pass");

        // Update the password.
        contract.update_site_password(pass_id, "new_encrypted_pass".to_string());

        let new_enc_pass = contract.get_site_password(accound_id, pass_id);
        assert_eq!(new_enc_pass, "new_encrypted_pass");
    }

    #[test]
    #[should_panic(expected = "NearpassNoSitePass: No site password found")]
    fn delete_site_password() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        let pass_id = contract.add_site_password("encrypted_pass".to_string());

        let encrypted_pass = contract.get_site_password(accound_id.clone(), pass_id);
        assert_eq!(encrypted_pass, "encrypted_pass");

        // Delete the password.
        contract.delete_site_password(pass_id);

        // Check if it is deleted.
        contract.get_site_password(accound_id, pass_id);
    }

    #[test]
    fn get_all_site_password_ids() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        contract.add_site_password("encrypted_pass".to_string());
        contract.add_site_password("new_encrypted_pass".to_string());

        let all_password_ids = contract.get_all_site_password_ids(accound_id);
        assert_eq!(all_password_ids, Some(vec![0, 1]));
    }

    #[test]
    fn get_site_passwords_by_ids() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        contract.add_site_password("encrypted_pass".to_string());
        contract.add_site_password("new_encrypted_pass".to_string());

        let enc_passes = contract.get_site_passwords_by_ids(accound_id, vec![0, 1]);
        assert_eq!(enc_passes, vec!["encrypted_pass", "new_encrypted_pass"]);
    }

    #[test]
    fn add_text() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        let text_id = contract.add_text("encrypted_text".to_string());

        let enc_text = contract.get_text(accound_id, text_id);
        assert_eq!(enc_text, "encrypted_text");
    }

    #[test]
    fn update_text() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        let text_id = contract.add_text("encrypted_text".to_string());

        let enc_text = contract.get_text(accound_id.clone(), text_id);
        assert_eq!(enc_text, "encrypted_text");

        // Update the text.
        contract.update_text(text_id, "new_encrypted_text".to_string());

        let new_enc_text = contract.get_text(accound_id, text_id);
        assert_eq!(new_enc_text, "new_encrypted_text");
    }

    #[test]
    #[should_panic(expected = "NearpassNoText: No text found")]
    fn delete_text() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        let text_id = contract.add_text("encrypted_text".to_string());

        let enc_text = contract.get_text(accound_id.clone(), text_id);
        assert_eq!(enc_text, "encrypted_text");

        // Delete the text.
        contract.delete_text(text_id);

        // Check if it is deleted.
        contract.get_text(accound_id, text_id);
    }

    #[test]
    fn get_all_text_ids() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        contract.add_text("encrypted_text".to_string());
        contract.add_text("new_encrypted_text".to_string());

        let text_ids = contract.get_all_text_ids(accound_id);
        assert_eq!(text_ids, Some(vec![0, 1]));
    }

    #[test]
    fn get_texts_by_ids() {
        let context = crate::tests::get_context(vec![], false);
        let accound_id = context.signer_account_id.to_string();
        testing_env!(context);

        let mut contract = NearPass::default();
        contract.add_text("encrypted_text".to_string());
        contract.add_text("new_encrypted_text".to_string());

        let enc_texts = contract.get_texts_by_ids(accound_id, vec![0, 1]);
        assert_eq!(enc_texts, vec!["encrypted_text", "new_encrypted_text"]);
    }
}
