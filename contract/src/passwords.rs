use near_sdk::borsh::BorshSerialize;
use near_sdk::collections::UnorderedSet;
use near_sdk::{env, near_bindgen, AccountId};

use crate::{hash, DataId, EncryptedData, NearPass, NearPassContract, StorageKey};

#[near_bindgen]
impl NearPass {
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
}

#[cfg(test)]
mod tests {
    use near_sdk::testing_env;
    use near_sdk::MockedBlockchain;

    use super::*;

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
}
