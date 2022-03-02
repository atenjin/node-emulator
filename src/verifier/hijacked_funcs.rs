#![allow(dead_code)]
#![allow(unused_variables)]


use std::any::TypeId;
use log::*;
use sp_api::ProofRecorder;
use sp_core::traits::TaskExecutorExt;
use sp_externalities::{set_and_run_with_externalities, Externalities, Extension, Extensions};
use sp_io::KillStorageResult;
use sp_runtime::traits::{Block as BlockT, HashFor};
use sp_std::vec::Vec;
use sp_storage::StateVersion;
use sp_trie::{CompactProof, MemoryDB};

type TrieBackend<B> = sp_state_machine::TrieBackend<MemoryDB<HashFor<B>>, HashFor<B>>;
type ProvingBackend<'a, B> = sp_state_machine::ProvingBackend<'a, MemoryDB<HashFor<B>>,  HashFor<B>>;
// type Ext<'a, B> = sp_state_machine::Ext<'a, HashFor<B>, TrieBackend<B>>;
type Ext<'a, B> = sp_state_machine::Ext<'a, HashFor<B>, ProvingBackend<'a, B>>;

fn with_externalities<F: FnOnce(&mut dyn Externalities) -> R, R>(f: F) -> R {
    sp_externalities::with_externalities(f).expect("Environmental externalities not set.")
}

/// Run the given closure with the externalities set.
pub(crate) fn run_with_externalities<B: BlockT, R, F: FnOnce() -> R>(
    backend: &ProvingBackend<B>,
    execute: F,
) -> R {

    let mut overlay = sp_state_machine::OverlayedChanges::default();
    let mut cache = Default::default();
    let mut extension = Extensions::new();
    extension.register(TaskExecutorExt::new(sp_core::testing::TaskExecutor::new()));
    let mut ext = Ext::<B>::new(&mut overlay, &mut cache, backend, Some(&mut extension));

    let pairs = ext.storage_pairs();
    println!("{:?}", pairs); // empty

    let r = set_and_run_with_externalities(&mut ext, || execute());

    let pairs = ext.storage_pairs();  // commit in future
    println!("{:?}", pairs);
    r
}

pub mod storage {
    use super::*;
    pub fn read(key: &[u8], value_out: &mut [u8], value_offset: u32) -> Option<u32> {
        match with_externalities(|ext| ext.storage(key)) {
            Some(value) => {
                let value_offset = value_offset as usize;
                let data = &value[value_offset.min(value.len())..];
                let written = sp_std::cmp::min(data.len(), value_out.len());
                value_out[..written].copy_from_slice(&data[..written]);
                Some(value.len() as u32)
            }
            None => None,
        }
    }

    pub fn set(key: &[u8], value: &[u8]) {
        with_externalities(|ext| ext.place_storage(key.to_vec(), Some(value.to_vec())))
    }

    pub fn get(key: &[u8]) -> Option<Vec<u8>> {
        with_externalities(|ext| ext.storage(key).clone())
    }

    pub fn exists(key: &[u8]) -> bool {
        with_externalities(|ext| ext.exists_storage(key))
    }

    pub fn clear(key: &[u8]) {
        with_externalities(|ext| ext.place_storage(key.to_vec(), None))
    }

    pub fn root() -> Vec<u8> {
        with_externalities(|ext| ext.storage_root(StateVersion::V1))
    }

    pub fn clear_prefix(prefix: &[u8], limit: Option<u32>) -> KillStorageResult {
        with_externalities(|ext| {
            let (all_removed, num_removed) = ext.clear_prefix(prefix, limit);
            match all_removed {
                true => KillStorageResult::AllRemoved(num_removed),
                false => KillStorageResult::SomeRemaining(num_removed),
            }
        })
    }

    pub fn append(key: &[u8], value: Vec<u8>) {
        with_externalities(|ext| ext.storage_append(key.to_vec(), value))
    }

    pub fn next_key(key: &[u8]) -> Option<Vec<u8>> {
        with_externalities(|ext| ext.next_storage_key(key))
    }

    pub fn start_transaction() {
        with_externalities(|ext| ext.storage_start_transaction())
    }

    pub fn rollback_transaction() {
        with_externalities(|ext| ext.storage_rollback_transaction().ok())
            .expect("No open transaction that can be rolled back.");
    }

    pub fn commit_transaction() {
        with_externalities(|ext| ext.storage_commit_transaction().ok())
            .expect("No open transaction that can be committed.");
    }
}

pub mod default_child_storage {
    use super::*;
    use sp_core::storage::ChildInfo;

    pub fn get(storage_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| ext.child_storage(&child_info, key))
    }

    pub fn read(
        storage_key: &[u8],
        key: &[u8],
        value_out: &mut [u8],
        value_offset: u32,
    ) -> Option<u32> {
        let child_info = ChildInfo::new_default(storage_key);
        match with_externalities(|ext| ext.child_storage(&child_info, key)) {
            Some(value) => {
                let value_offset = value_offset as usize;
                let data = &value[value_offset.min(value.len())..];
                let written = sp_std::cmp::min(data.len(), value_out.len());
                value_out[..written].copy_from_slice(&data[..written]);
                Some(value.len() as u32)
            }
            None => None,
        }
    }

    pub fn set(storage_key: &[u8], key: &[u8], value: &[u8]) {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| {
            ext.place_child_storage(&child_info, key.to_vec(), Some(value.to_vec()))
        })
    }

    pub fn clear(storage_key: &[u8], key: &[u8]) {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| ext.place_child_storage(&child_info, key.to_vec(), None))
    }

    pub fn kill(storage_key: &[u8], limit: Option<u32>) -> KillStorageResult {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| {
            let (all_removed, num_removed) = ext.kill_child_storage(&child_info, limit);
            match all_removed {
                true => KillStorageResult::AllRemoved(num_removed),
                false => KillStorageResult::SomeRemaining(num_removed),
            }
        })
    }

    pub fn exists(storage_key: &[u8], key: &[u8]) -> bool {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| ext.exists_child_storage(&child_info, key))
    }

    pub fn clear_prefix(
        storage_key: &[u8],
        prefix: &[u8],
        limit: Option<u32>,
    ) -> KillStorageResult {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| {
            let (all_removed, num_removed) = ext.clear_child_prefix(&child_info, prefix, limit);
            match all_removed {
                true => KillStorageResult::AllRemoved(num_removed),
                false => KillStorageResult::SomeRemaining(num_removed),
            }
        })
    }

    pub fn storage_root(storage_key: &[u8]) -> Vec<u8> {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| ext.child_storage_root(&child_info, StateVersion::V1))
    }

    pub fn next_key(storage_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        let child_info = ChildInfo::new_default(storage_key);
        with_externalities(|ext| ext.next_child_storage_key(&child_info, key))
    }
}

pub mod trie {
    use super::*;
    use crate::verifier::hasher::*;
    use sp_core::H256;
    use sp_trie::*;

    pub fn blake2_256_ordered_root(input: Vec<Vec<u8>>) -> H256 {
        // jiaquan: We use LayoutV1 here, instead of V0
        LayoutV1::<blake2::Blake2Hasher>::ordered_trie_root(input)
    }

    pub fn blake2_256_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
        // jiaquan: We use LayoutV1 here, instead of V0
        LayoutV1::<blake2::Blake2Hasher>::trie_root(input)
    }

    pub fn blake2_256_verify_proof(
        root: H256,
        proof: &[Vec<u8>],
        key: &[u8],
        value: &[u8],
    ) -> bool {
        // jiaquan: We use LayoutV1 here, instead of V0
        sp_trie::verify_trie_proof::<LayoutV1<blake2::Blake2Hasher>, _, _, _>(
            &root,
            proof,
            &[(key, Some(value))],
        )
        .is_ok()
    }

    pub fn keccak_256_ordered_root(input: Vec<Vec<u8>>) -> H256 {
        // jiaquan: We use LayoutV1 here, instead of V0
        LayoutV1::<keccak::KeccakHasher>::ordered_trie_root(input)
    }

    pub fn keccak_256_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
        // jiaquan: We use LayoutV1 here, instead of V0
        LayoutV1::<keccak::KeccakHasher>::trie_root(input)
    }

    pub fn keccak_256_verify_proof(
        root: H256,
        proof: &[Vec<u8>],
        key: &[u8],
        value: &[u8],
    ) -> bool {
        // jiaquan: We use LayoutV1 here, instead of V0
        sp_trie::verify_trie_proof::<LayoutV1<keccak::KeccakHasher>, _, _, _>(
            &root,
            proof,
            &[(key, Some(value))],
        )
        .is_ok()
    }
}

pub mod hashing {
    pub fn blake2_128(data: &[u8]) -> [u8; 16] {
        use blake2::{
            digest::{Update, VariableOutput},
            VarBlake2b,
        };

        let mut hasher = VarBlake2b::new(16).unwrap();
        hasher.update(data);
        let mut data_hash = [0_u8; 16];
        hasher.finalize_variable(|result| {
            data_hash.copy_from_slice(result);
        });
        data_hash
    }

    pub fn blake2_256(data: &[u8]) -> [u8; 32] {
        use blake2::{
            digest::{Update, VariableOutput},
            VarBlake2b,
        };

        let mut hasher = VarBlake2b::new(32).unwrap();
        hasher.update(data);
        let mut data_hash = [0_u8; 32];
        hasher.finalize_variable(|result| {
            data_hash.copy_from_slice(result);
        });
        data_hash
    }

    pub fn keccak_256(data: &[u8]) -> [u8; 32] {
        use tiny_keccak::{Hasher, Keccak};

        let mut keccak = Keccak::v256();
        let mut data_hash = [0_u8; 32];
        keccak.update(data);
        keccak.finalize(&mut data_hash);
        data_hash
    }

    pub fn keccak_512(data: &[u8]) -> [u8; 64] {
        use tiny_keccak::{Hasher, Keccak};

        let mut keccak = Keccak::v512();
        let mut data_hash = [0_u8; 64];
        keccak.update(data);
        keccak.finalize(&mut data_hash);
        data_hash
    }

    pub fn sha2_256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(data);
        let mut data_hash = [0_u8; 32];
        data_hash.copy_from_slice(&hasher.finalize());
        data_hash
    }

    pub fn twox_128(data: &[u8]) -> [u8; 16] {
        use byteorder::{ByteOrder, LittleEndian};
        use core::hash::Hasher;

        let mut h0 = twox_hash::XxHash::with_seed(0);
        let mut h1 = twox_hash::XxHash::with_seed(1);
        h0.write(data);
        h1.write(data);
        let r0 = h0.finish();
        let r1 = h1.finish();

        let mut data_hash = [0_u8; 16];
        LittleEndian::write_u64(&mut data_hash[0..8], r0);
        LittleEndian::write_u64(&mut data_hash[8..16], r1);
        data_hash
    }

    pub fn twox_256(data: &[u8]) -> [u8; 32] {
        use byteorder::{ByteOrder, LittleEndian};
        use core::hash::Hasher;

        let mut h0 = twox_hash::XxHash::with_seed(0);
        let mut h1 = twox_hash::XxHash::with_seed(1);
        let mut h2 = twox_hash::XxHash::with_seed(2);
        let mut h3 = twox_hash::XxHash::with_seed(3);
        h0.write(data);
        h1.write(data);
        h2.write(data);
        h3.write(data);
        let r0 = h0.finish();
        let r1 = h1.finish();
        let r2 = h2.finish();
        let r3 = h3.finish();

        let mut data_hash = [0_u8; 32];
        LittleEndian::write_u64(&mut data_hash[0..8], r0);
        LittleEndian::write_u64(&mut data_hash[8..16], r1);
        LittleEndian::write_u64(&mut data_hash[16..24], r2);
        LittleEndian::write_u64(&mut data_hash[24..32], r3);
        data_hash
    }

    pub fn twox_64(data: &[u8]) -> [u8; 8] {
        use byteorder::{ByteOrder, LittleEndian};
        use core::hash::Hasher;

        let mut h0 = twox_hash::XxHash::with_seed(0);
        h0.write(data);
        let r0 = h0.finish();

        let mut data_hash = [0_u8; 8];
        LittleEndian::write_u64(&mut data_hash[0..8], r0);
        data_hash
    }
}

pub mod crypto {
    use super::*;
    // use geode_common::{crypto::*, crypto_types::*};
    use sp_core::{crypto::KeyTypeId, ecdsa, ed25519, sr25519, Pair};
    use sp_io::EcdsaVerifyError;

    pub fn ecdsa_batch_verify(sig: &ecdsa::Signature, msg: &[u8], pub_key: &ecdsa::Public) -> bool {
        error!(
            "No VerificationExt supported yet, return true directly in ecdsa_batch_verify method"
        );
        true
    }

    pub fn ecdsa_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> ecdsa::Public {
        unimplemented!("")
        // error!(
        //     "No VerificationExt supported yet in ecdsa_generate method, won't save the ecdsa key"
        // );
        // if let Some(seed_bytes) = seed {
        //     let mut seed = [0u8; 32];
        //     seed.copy_from_slice(&seed_bytes);
        //     let (_prvkey, pubkey) = secp256k1_gen_keypair_with_seed(&seed).unwrap();
        //     convert_to_sp_core_ecdsa_pubkey(&pubkey).unwrap()
        // } else {
        //     let (_prvkey, pubkey) = secp256k1_gen_keypair().unwrap();
        //     convert_to_sp_core_ecdsa_pubkey(&pubkey).unwrap()
        // }
    }

    pub fn ecdsa_public_keys(id: KeyTypeId) -> Vec<ecdsa::Public> {
        error!("No VerificationExt supported yet in ecdsa_public_keys method");
        Vec::new()
    }

    pub fn ecdsa_sign(
        id: KeyTypeId,
        pub_key: &ecdsa::Public,
        msg: &[u8],
    ) -> Option<ecdsa::Signature> {
        error!("No VerificationExt supported yet in ecdsa_sign method");
        None
    }

    pub fn ecdsa_sign_prehashed(
        id: KeyTypeId,
        pub_key: &ecdsa::Public,
        msg: &[u8; 32],
    ) -> Option<ecdsa::Signature> {
        error!("No VerificationExt supported yet in ecdsa_sign_prehashed method");
        None
    }

    pub fn ecdsa_verify(sig: &ecdsa::Signature, msg: &[u8], pub_key: &ecdsa::Public) -> bool {
        match sig.recover(msg) {
            Some(pubkey) => pubkey.as_ref() == pub_key.as_ref(),
            None => false,
        }
    }

    pub fn ecdsa_verify_prehashed(
        sig: &ecdsa::Signature,
        msg: &[u8; 32],
        pub_key: &ecdsa::Public,
    ) -> bool {
        match sig.recover_prehashed(msg) {
            Some(pubkey) => pubkey.as_ref() == pub_key.as_ref(),
            None => false,
        }
    }

    pub fn ed25519_batch_verify(
        sig: &ed25519::Signature,
        msg: &[u8],
        pub_key: &ed25519::Public,
    ) -> bool {
        error!(
            "No VerificationExt supported yet, return true directly in ed25519_batch_verify method"
        );
        true
    }

    pub fn ed25519_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> ed25519::Public {
        error!("No VerificationExt supported yet in ed25519_generate method, won't save the ed25519 key");
        match seed {
            Some(s) => {
                let mut seed_bytes = [0u8; 32];
                seed_bytes.copy_from_slice(&s);
                let pair = ed25519::Pair::from_seed(&seed_bytes);
                pair.public()
            }
            None => {
                unimplemented!("")
            }
        }
    }

    pub fn ed25519_public_keys(id: KeyTypeId) -> Vec<ed25519::Public> {
        error!("No VerificationExt supported yet in ed25519_public_keys method");
        Vec::new()
    }

    pub fn ed25519_sign(
        id: KeyTypeId,
        pub_key: &ed25519::Public,
        msg: &[u8],
    ) -> Option<ed25519::Signature> {
        error!("No VerificationExt supported yet in ed25519_sign method");
        None
    }

    pub fn ed25519_verify(sig: &ed25519::Signature, msg: &[u8], pub_key: &ed25519::Public) -> bool {
        ed25519::Pair::verify(sig, msg, pub_key)
    }

    pub fn finish_batch_verify() -> bool {
        error!("No VerificationExt supported yet in finish_batch_verify method");
        true
    }

    pub fn secp256k1_ecdsa_recover(
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<[u8; 64], EcdsaVerifyError> {
        unimplemented!("")
        // let mut r = [0_u8; 32];
        // let mut s = [0_u8; 32];
        // r.copy_from_slice(&sig[..32]);
        // s.copy_from_slice(&sig[32..64]);
        // let signature = Secp256k1RecoverableSignature {
        //     v: if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8,
        //     r,
        //     s,
        // };
        // match secp256k1_recover_pubkey(&signature, msg) {
        //     Ok(pubkey) => {
        //         let mut pubkey_slices = [0_u8; 64];
        //         pubkey_slices[..32].copy_from_slice(&pubkey.gx);
        //         pubkey_slices[32..].copy_from_slice(&pubkey.gy);
        //         Ok(pubkey_slices)
        //     }
        //     Err(_) => Err(EcdsaVerifyError::BadSignature),
        // }
    }

    pub fn secp256k1_ecdsa_recover_compressed(
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<[u8; 33], EcdsaVerifyError> {
        unimplemented!("")
        // let mut r = [0_u8; 32];
        // let mut s = [0_u8; 32];
        // r.copy_from_slice(&sig[..32]);
        // s.copy_from_slice(&sig[32..64]);
        // let signature = Secp256k1RecoverableSignature {
        //     v: if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as u8,
        //     r,
        //     s,
        // };
        // match secp256k1_recover_pubkey(&signature, msg) {
        //     Ok(pubkey) => {
        //         let pubkey = convert_to_sp_core_ecdsa_pubkey(&pubkey).unwrap();
        //         Ok(pubkey.0)
        //     }
        //     Err(_) => Err(EcdsaVerifyError::BadSignature),
        // }
    }

    pub fn sr25519_batch_verify(
        sig: &sr25519::Signature,
        msg: &[u8],
        pub_key: &sr25519::Public,
    ) -> bool {
        error!(
            "No VerificationExt supported yet, return true directly in sr25519_batch_verify method"
        );
        true
    }

    pub fn sr25519_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> sr25519::Public {
        unimplemented!("")
        // error!("No VerificationExt supported yet in sr25519_generate method, won't save the sr25519 key");
        // if let Some(seed_bytes) = seed {
        //     let mut seed = [0u8; 32];
        //     seed.copy_from_slice(&seed_bytes);
        //     let (_prvkey, pubkey) = sr25519_gen_keypair_with_seed(&seed).unwrap();
        //     sr25519::Public::from_raw(pubkey.compressed_point)
        // } else {
        //     let (_prvkey, pubkey) = sr25519_gen_keypair().unwrap();
        //     sr25519::Public::from_raw(pubkey.compressed_point)
        // }
    }

    pub fn sr25519_public_keys(id: KeyTypeId) -> Vec<sr25519::Public> {
        error!("No VerificationExt supported yet in sr25519_public_keys method");
        Vec::new()
    }

    pub fn sr25519_sign(
        id: KeyTypeId,
        pub_key: &sr25519::Public,
        msg: &[u8],
    ) -> Option<sr25519::Signature> {
        error!("No VerificationExt supported yet in sr25519_sign method");
        None
    }

    pub fn sr25519_verify(sig: &sr25519::Signature, msg: &[u8], pub_key: &sr25519::Public) -> bool {
        unimplemented!("")
        // let signature: Sr25519Signature = Sr25519Signature { signature_bytes: sig.0 };
        // let pubkey: Sr25519PublicKey =
        //     Sr25519PublicKey { compressed_point: pub_key.as_array_ref().clone() };
        // sr25519_verify_signature(&pubkey, msg, &signature).unwrap()
    }

    pub fn start_batch_verify() {
        error!("No VerificationExt supported yet in start_batch_verify method");
    }
}

pub mod misc {
    use super::*;
    pub fn print_hex(data: &[u8]) {
        // println!("[DEBUG] print_hex: {:?}", data);
        // println!("[DEBUG] hex::encode: {:?}", hex::encode(data));
        debug!(target: "runtime", "0x{}", hex::encode(data));
    }

    pub fn print_utf8(utf8: &[u8]) {
        // println!("[DEBUG] print_utf8: {:?}", utf8);
        if let Ok(data) = std::str::from_utf8(utf8) {
            // println!("[DEBUG] data: {:?}", data);
            debug!(target: "runtime", "{}", data);
        }
    }

    pub fn runtime_version(wasm: &[u8]) -> Option<Vec<u8>> {
        // The sp_core::trait is implemented in std mode,
        // need to figure out how to retrieve the information in ReadRuntimeVersionExt
        // Or we can store the runtime version information inside the binary
        error!("No ReadRuntimeVersionExt supported yet in runtime_version, return None instead");
        None
    }
}
