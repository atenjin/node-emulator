use serde::{Serialize, Deserialize};

pub mod blake2 {
    use hash256_std_hasher::Hash256StdHasher;
    use hash_db::Hasher;
    use sp_core::H256;
    use sp_runtime::traits::Hash;
    use sp_std::vec::Vec;
    use sp_storage::StateVersion;
    use super::*;
    /// Concrete implementation of Hasher using Blake2b 256-bit hashes
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub struct Blake2Hasher;

    impl Hasher for Blake2Hasher {
        type Out = H256;
        type StdHasher = Hash256StdHasher;
        const LENGTH: usize = 32;

        fn hash(x: &[u8]) -> Self::Out {
            crate::verifier::hijacked_funcs::hashing::blake2_256(x).into()
        }
    }

    impl Hash for Blake2Hasher {
        type Output = H256;

        fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, _: StateVersion) -> Self::Output {
            crate::verifier::hijacked_funcs::trie::blake2_256_root(input)
        }

        fn ordered_trie_root(input: Vec<Vec<u8>>, _: StateVersion) -> Self::Output {
            crate::verifier::hijacked_funcs::trie::blake2_256_ordered_root(input)
        }
    }
}

pub mod keccak {
    use hash256_std_hasher::Hash256StdHasher;
    use hash_db::Hasher;
    use sp_core::hash::H256;
    use sp_runtime::traits::Hash;
    use sp_std::vec::Vec;
    use sp_storage::StateVersion;
    use super::*;

    /// Concrete implementation of Hasher using Keccak 256-bit hashes
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub struct KeccakHasher;

    impl Hasher for KeccakHasher {
        type Out = H256;
        type StdHasher = Hash256StdHasher;
        const LENGTH: usize = 32;

        fn hash(x: &[u8]) -> Self::Out {
            crate::verifier::hijacked_funcs::hashing::keccak_256(x).into()
        }
    }

    impl Hash for KeccakHasher {
        type Output = sp_core::H256;

        fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, _: StateVersion) -> Self::Output {
            crate::verifier::hijacked_funcs::trie::keccak_256_root(input)
        }

        fn ordered_trie_root(input: Vec<Vec<u8>>, _: StateVersion) -> Self::Output {
            crate::verifier::hijacked_funcs::trie::keccak_256_ordered_root(input)
        }
    }
}
