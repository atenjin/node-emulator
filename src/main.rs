// #![no_std]
mod verifier;
mod alt_producer_runtime;

use sp_runtime::RuntimeDebug;
use codec::{Encode, Decode};

fn main() {
    verifier::verifier()
}

// #[derive(PartialEq, Eq, Decode, Clone)]
// #[cfg_attr(feature = "std", derive(Debug, Encode))]
#[derive(PartialEq, Eq, Decode, Clone, Debug, Encode)]
pub struct ValidationParams {
    /// Previous head-data.
    pub parent_head: HeadData,
    /// The collation body.
    pub block_data: BlockData,
    // TODO other fields
}

/// Node head data included in the chain.
#[derive(
    PartialEq,
    Eq,
    Clone,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    RuntimeDebug,
    derive_more::From,
    Default,
    Hash
)]
pub struct HeadData(pub Vec<u8>);
/// Layer2 node block data.
///
/// Contains everything required to validate para-block, may contain block and witness data.
#[derive(PartialEq, Eq, Clone, Encode, Decode, derive_more::From, RuntimeDebug)]
pub struct BlockData(pub Vec<u8>);
