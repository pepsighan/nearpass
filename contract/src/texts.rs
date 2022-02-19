use near_sdk::borsh::BorshSerialize;
use near_sdk::collections::LookupMap;
use near_sdk::{env, near_bindgen, AccountId};

use crate::{hash, DataId, EncryptedData, NearPass, NearPassContract, StorageKey};

#[near_bindgen]
impl NearPass {
    /// Add a text for the account.
    pub fn add_text(&mut self, enc_data: EncryptedData) -> DataId {
        let account_id = env::signer_account_id();
        env::log(format!("Add a text for account '{}'", account_id).as_bytes());

        let cur_data_id = self.current_data_id;
        self.current_data_id += 1;

        // Add the site password.
        self.data_map.insert(&cur_data_id, &enc_data);

        let mut acc_text_ids = self.text_id_by_account.get(&account_id);
        let cur_text_index = self.count_text_id_by_account.get(&account_id).unwrap_or(0);

        // If the account id is not present, create one.
        if acc_text_ids.is_none() {
            acc_text_ids = Option::Some(LookupMap::new(
                StorageKey::TextIdByAccountInner {
                    account_id_hash: hash::hash_account_id(&account_id),
                }
                .try_to_vec()
                .unwrap(),
            ));
            self.text_id_by_account
                .insert(&account_id, acc_text_ids.as_ref().unwrap());
        }

        // Record a new text for the account.
        let mut acc_text_ids = acc_text_ids.unwrap();
        acc_text_ids.insert(&cur_text_index, &cur_data_id);
        // Increment the count.
        self.count_text_id_by_account
            .insert(&account_id, &(cur_text_index + 1));

        return cur_data_id;
    }

    /// Panics if the site password is not owned by the account.
    /// Returns account if it is needed by the caller.
    fn panic_if_account_invalid_for_text(
        &self,
        account_id: &AccountId,
        text_id: DataId,
    ) -> LookupMap<u64, DataId> {
        let account = self.text_id_by_account.get(&account_id);
        assert!(account.is_some(), "NearpassNoText: No text found");

        let account = account.unwrap();
        assert!(
            account.get(&text_id).is_some(),
            "NearpassNoText: No text found"
        );

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
        let text_id_count = self.count_text_id_by_account.get(&account_id).unwrap_or(0);

        Some(
            (0..text_id_count)
                .into_iter()
                .map(|index| text_ids.get(&index).unwrap())
                .collect(),
        )
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
        let all_owned = text_ids.iter().all(|it| account.get(it).is_some());
        assert!(all_owned, "NearpassNoText: No text found");

        text_ids
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
