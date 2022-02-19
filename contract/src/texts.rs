use near_sdk::borsh::BorshSerialize;
use near_sdk::collections::LookupMap;
use near_sdk::{env, near_bindgen};

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
}
