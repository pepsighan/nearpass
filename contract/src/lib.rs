use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::{env, near_bindgen, setup_alloc, AccountId, CryptoHash};

mod hash;
mod passwords;
mod texts;

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
    /// Using LookupMap to store a list of PassId instead of UnorderedSet because
    /// UnorderedSet does not iterate properly due to: https://github.com/near/near-sdk-rs/issues/733.
    site_password_id_by_account: LookupMap<AccountId, LookupMap<u64, DataId>>,
    /// Stores the count of password ids for each account. Need to store this because of reasons
    /// above.
    count_site_password_id_by_account: LookupMap<AccountId, u64>,
    /// Collection of all text data ids for each account.
    text_id_by_account: LookupMap<AccountId, LookupMap<u64, DataId>>,
    /// Stores the count of text ids for each account.
    count_text_id_by_account: LookupMap<AccountId, u64>,
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
    CountSitePasswordIdByAccount,
    TextIdByAccount,
    TextIdByAccountInner { account_id_hash: CryptoHash },
    CountTextIdByAccount,
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
            count_site_password_id_by_account: LookupMap::new(
                StorageKey::CountSitePasswordIdByAccount
                    .try_to_vec()
                    .unwrap(),
            ),
            text_id_by_account: LookupMap::new(StorageKey::TextIdByAccount.try_to_vec().unwrap()),
            count_text_id_by_account: LookupMap::new(
                StorageKey::CountTextIdByAccount.try_to_vec().unwrap(),
            ),
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
}
