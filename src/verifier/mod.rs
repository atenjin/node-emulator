#![allow(dead_code)]

mod hasher;
mod hijacked_funcs;

use codec::{Encode, Decode};

use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_trie::MemoryDB;

use crate::ValidationParams;

// todo change this to alt_producer_runtime after test.
// use crate::example_runtime as runtime;
use crate::alt_producer_runtime as runtime;
use runtime::{Block, Header};

use hijacked_funcs::*;

pub fn verifier() {
    // todo prepare some test data
    let test1 = runtime::test_data_1();
    // println!("Generate test data succeed!");
    for p in test1 {
        validate_block(p);
    }
}

pub fn validate_block(params: ValidationParams) {
    // println!("Init guard");
    // let _guard = (
    //     // Replace storage calls with our own implementations
    //     sp_io::storage::host_read.replace_implementation(storage::read),
    //     sp_io::storage::host_set.replace_implementation(storage::set),
    //     sp_io::storage::host_get.replace_implementation(storage::get),
    //     sp_io::storage::host_exists.replace_implementation(storage::exists),
    //     sp_io::storage::host_clear.replace_implementation(storage::clear),
    //     sp_io::storage::host_root.replace_implementation(storage::root),
    //     sp_io::storage::host_clear_prefix.replace_implementation(storage::clear_prefix),
    //     sp_io::storage::host_append.replace_implementation(storage::append),
    //     sp_io::storage::host_next_key.replace_implementation(storage::next_key),
    //     sp_io::storage::host_start_transaction.replace_implementation(storage::start_transaction),
    //     sp_io::storage::host_rollback_transaction
    //         .replace_implementation(storage::rollback_transaction),
    //     sp_io::storage::host_commit_transaction.replace_implementation(storage::commit_transaction),
    //     sp_io::default_child_storage::host_get.replace_implementation(default_child_storage::get),
    //     sp_io::default_child_storage::host_read.replace_implementation(default_child_storage::read),
    //     sp_io::default_child_storage::host_set.replace_implementation(default_child_storage::set),
    //     sp_io::default_child_storage::host_clear
    //         .replace_implementation(default_child_storage::clear),
    //     sp_io::default_child_storage::host_storage_kill
    //         .replace_implementation(default_child_storage::kill),
    //     sp_io::default_child_storage::host_exists
    //         .replace_implementation(default_child_storage::exists),
    //     sp_io::default_child_storage::host_clear_prefix
    //         .replace_implementation(default_child_storage::clear_prefix),
    //     sp_io::default_child_storage::host_root
    //         .replace_implementation(default_child_storage::storage_root),
    //     sp_io::default_child_storage::host_next_key
    //         .replace_implementation(default_child_storage::next_key),
    //     // Replace trie calls
    //     sp_io::trie::host_blake2_256_ordered_root
    //         .replace_implementation(trie::blake2_256_ordered_root),
    //     sp_io::trie::host_blake2_256_root.replace_implementation(trie::blake2_256_root),
    //     sp_io::trie::host_blake2_256_verify_proof
    //         .replace_implementation(trie::blake2_256_verify_proof),
    //     sp_io::trie::host_keccak_256_ordered_root
    //         .replace_implementation(trie::keccak_256_ordered_root),
    //     sp_io::trie::host_keccak_256_root.replace_implementation(trie::keccak_256_root),
    //     sp_io::trie::host_keccak_256_verify_proof
    //         .replace_implementation(trie::keccak_256_verify_proof),
    //     // Replace hashing calls
    //     sp_io::hashing::host_blake2_128.replace_implementation(hashing::blake2_128),
    //     sp_io::hashing::host_blake2_256.replace_implementation(hashing::blake2_256),
    //     sp_io::hashing::host_keccak_256.replace_implementation(hashing::keccak_256),
    //     sp_io::hashing::host_keccak_512.replace_implementation(hashing::keccak_512),
    //     sp_io::hashing::host_sha2_256.replace_implementation(hashing::sha2_256),
    //     sp_io::hashing::host_twox_128.replace_implementation(hashing::twox_128),
    //     sp_io::hashing::host_twox_256.replace_implementation(hashing::twox_256),
    //     sp_io::hashing::host_twox_64.replace_implementation(hashing::twox_64),
    //     // Replace crypto calls
    //     sp_io::crypto::host_ecdsa_batch_verify.replace_implementation(crypto::ecdsa_batch_verify),
    //     sp_io::crypto::host_ecdsa_generate.replace_implementation(crypto::ecdsa_generate),
    //     sp_io::crypto::host_ecdsa_public_keys.replace_implementation(crypto::ecdsa_public_keys),
    //     sp_io::crypto::host_ecdsa_sign.replace_implementation(crypto::ecdsa_sign),
    //     // sp_io::crypto::host_ecdsa_sign_prehashed.replace_implementation(crypto::ecdsa_sign_prehashed),
    //     sp_io::crypto::host_ecdsa_verify.replace_implementation(crypto::ecdsa_verify),
    //     // sp_io::crypto::host_ecdsa_verify_prehashed.replace_implementation(crypto::ecdsa_verify_prehashed),
    //     sp_io::crypto::host_ed25519_batch_verify
    //         .replace_implementation(crypto::ed25519_batch_verify),
    //     sp_io::crypto::host_ed25519_generate.replace_implementation(crypto::ed25519_generate),
    //     sp_io::crypto::host_ed25519_public_keys.replace_implementation(crypto::ed25519_public_keys),
    //     sp_io::crypto::host_ed25519_sign.replace_implementation(crypto::ed25519_sign),
    //     sp_io::crypto::host_ed25519_verify.replace_implementation(crypto::ed25519_verify),
    //     sp_io::crypto::host_finish_batch_verify.replace_implementation(crypto::finish_batch_verify),
    //     sp_io::crypto::host_secp256k1_ecdsa_recover
    //         .replace_implementation(crypto::secp256k1_ecdsa_recover),
    //     sp_io::crypto::host_secp256k1_ecdsa_recover_compressed
    //         .replace_implementation(crypto::secp256k1_ecdsa_recover_compressed),
    //     sp_io::crypto::host_sr25519_batch_verify
    //         .replace_implementation(crypto::sr25519_batch_verify),
    //     sp_io::crypto::host_sr25519_generate.replace_implementation(crypto::sr25519_generate),
    //     sp_io::crypto::host_sr25519_public_keys.replace_implementation(crypto::sr25519_public_keys),
    //     sp_io::crypto::host_sr25519_sign.replace_implementation(crypto::sr25519_sign),
    //     sp_io::crypto::host_sr25519_verify.replace_implementation(crypto::sr25519_verify),
    //     sp_io::crypto::host_start_batch_verify.replace_implementation(crypto::start_batch_verify),
    //     sp_io::misc::host_print_hex.replace_implementation(misc::print_hex),
    //     sp_io::misc::host_print_utf8.replace_implementation(misc::print_utf8),
    //     sp_io::misc::host_runtime_version.replace_implementation(misc::runtime_version),
    // );

    let block_data =
        NodeBlockData::decode(&mut &params.block_data.0[..]).expect("decode must success");
    // println!("Init block_data");
    let parent_head = Header::decode(&mut &params.parent_head.0[..]).expect("Invalid parent head");
    // println!("parent_head: {:?}", parent_head);

    let (header, extrinsics, storage_proof) = block_data.deconstruct();
    // println!("header: {:?}", header);
    // println!("extrinsics: {:?}", extrinsics);
    // println!("storage_proof: {:?}", storage_proof);
    let block = <Block as BlockT>::new(header, extrinsics);
    // println!("block: {:?}", block);
    // TODO check prev hash or something else.
    // assert!(parent_head.hash() == *block.header().parent_hash(), "Invalid parent hash",);

    // Uncompress
    let mut db = MemoryDB::default();
    // println!("Init DB");
    // let root = match sp_trie::decode_compact::<sp_trie::LayoutV1<hasher::blake2::Blake2Hasher>, _, _>(
    let root = match sp_trie::decode_compact::<sp_trie::LayoutV1<<Header as HeaderT>::Hashing>, _, _>(
        &mut db,
        storage_proof.iter_compact_encoded_nodes(),
        Some(parent_head.state_root()),
    ) {
        Ok(root) => root,
        Err(_) => panic!("Compact proof decoding failure."),
    };
    // println!("root: {:?}", root);
    sp_std::mem::drop(storage_proof);

    // println!("Init backend");
    // let backend = sp_state_machine::TrieBackend::new(db, root);
    let backend = sp_state_machine::TrieBackend::new(db, root);
    let recorder = sp_state_machine::ProofRecorder::<<Block as BlockT>::Hash>::default();

    // wrap proof
    let proving_backend = sp_state_machine::ProvingBackend::new_with_recorder(
        &backend,
        recorder.clone(),
    );


    // backend from proof
    println!("before exec:{:}", backend.root());

    // println!("Before execute_block");
    // TODO check inherent data
    // run_with_externalities::<B, _, _>(&backend, || {});
    run_with_externalities::<Block, _, _>(&proving_backend, || {
        set_and_run_with_validation_params(params, || {
            // execute block and TODO: handle result in future
            // use codec::Encode;
            // let header = block.header();
            // header.digest().logs().iter().for_each(|d| {
            //     // println!("execute_block|d:{:?}|encoded:{:?}", d, d.encode());
            // });
            runtime::Executive::execute_block(block);
            // // TODO other check

            // sp_io::storage::set(&[1], &[1]);
            // sp_io::storage::set(&[2], &vec![2;33]);
            // let root = sp_io::storage::root();
            // println!("root:{:}", hex::encode(root));

            // let mut msg = [0; 32];
            // msg.copy_from_slice(&hex::decode("7a3827a60050145e7defa1fafc41b7c79119f66494c5f949aa6744ed38bcaae0").expect(""));
            // let mut sig = [0; 65];
            // sig.copy_from_slice(
            //     &hex::decode("dfcc727f44ae1a6454fb6365f5fd5484edc05c4eb18ed9326a72202b4cdbe8b4726f56132afdf0ca8cecafe127a8122a1890dc5f06078c5f37b4b22a36aace4501").expect("")
            // );
            // let pubkey = hex::decode("509540919faacf9ab52146c9aa40db68172d83777250b28e4679176e49ccdd9fa213197dc0666e85529d6c9dda579c1295d61c417f01505765481e89a4016f02").expect("");
            // let addr = hex::decode("f24ff3a9cf04c71dbc94d0b566f7a27b94566cac").expect("");
            // match hijacked_funcs::crypto::secp256k1_ecdsa_recover(&sig, &msg) {
            //     Ok(r) => {
            //         assert_eq!(r.as_slice(), pubkey.as_slice());
            //     }
            //     Err(e) => {
            //         panic!("");
            //     }
            // }
        })
    });
    println!("after exec:{:}", backend.root());
    let proof = recorder.to_storage_proof();
    println!("proof:{:}", hex::encode(proof.encode()));
}

// Stores the [`ValidationParams`] that are being passed to `validate_block`.
//
// This value will only be set when a parachain validator validates a given `PoV`.
environmental::environmental!(VALIDATION_PARAMS: ValidationParams);

/// Execute the given closure with the [`ValidationParams`].
///
/// Returns `None` if the [`ValidationParams`] are not set, because the code is currently not being
/// executed in the context of `validate_block`.
pub(crate) fn with_validation_params<R>(f: impl FnOnce(&ValidationParams) -> R) -> Option<R> {
    VALIDATION_PARAMS::with(|v| f(v))
}

/// Set the [`ValidationParams`] for the local context and execute the given closure in this context.
fn set_and_run_with_validation_params<R>(mut params: ValidationParams, f: impl FnOnce() -> R) -> R {
    VALIDATION_PARAMS::using(&mut params, f)
}

/// The node block that is created by a producer.
///
/// This is send as PoV (proof of validity block) to the verifiers. There it will be
/// passed to the SGX validation to be validated.
#[derive(codec::Encode, codec::Decode, Clone)]
pub struct NodeBlockData {
    /// The header of the parachain block.
    pub(crate) header: Header,
    /// The extrinsics of the parachain block.
    pub(crate) extrinsics: sp_std::vec::Vec<<Block as BlockT>::Extrinsic>,
    /// The data that is required to emulate the storage accesses executed by all extrinsics.
    pub(crate) storage_proof: sp_trie::CompactProof,
}

impl NodeBlockData {
    /// Creates a new instance of `Self`.
    pub fn new(
        header: Header,
        extrinsics: sp_std::vec::Vec<<Block as BlockT>::Extrinsic>,
        storage_proof: sp_trie::CompactProof,
    ) -> Self {
        Self { header, extrinsics, storage_proof }
    }

    /// Convert `self` into the stored block.
    pub fn into_block(self) -> Block {
        Block::new(self.header, self.extrinsics)
    }

    /// Convert `self` into the stored header.
    pub fn into_header(self) -> Header {
        self.header
    }

    /// Returns the header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Returns the extrinsics.
    pub fn extrinsics(&self) -> &[<Block as BlockT>::Extrinsic] {
        &self.extrinsics
    }

    /// Returns the [`CompactProof`](sp_trie::CompactProof).
    pub fn storage_proof(&self) -> &sp_trie::CompactProof {
        &self.storage_proof
    }

    /// Deconstruct into the inner parts.
    pub fn deconstruct(
        self,
    ) -> (Header, sp_std::vec::Vec<<Block as BlockT>::Extrinsic>, sp_trie::CompactProof) {
        (self.header, self.extrinsics, self.storage_proof)
    }
}
