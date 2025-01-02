use alloy_primitives::aliases::B32;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct LatestMessage {
    pub epoch: u64,
    pub root: B32,
}
