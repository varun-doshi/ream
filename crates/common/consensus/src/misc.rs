use std::cmp::max;

use alloy_primitives::{aliases::B32, B256};
use anyhow::ensure;
use ethereum_hashing::hash;
use tree_hash::TreeHash;

use crate::{
    deneb::beacon_state::BeaconState,
    fork_choice::helpers::constants::{
        MAX_EFFECTIVE_BALANCE, MAX_RANDOM_BYTE, MAX_SEED_LOOKAHEAD, SHUFFLE_ROUND_COUNT,
        SLOTS_PER_EPOCH,
    },
    fork_data::ForkData,
    signing_data::SigningData,
};

pub fn compute_signing_root<SSZObject: TreeHash>(ssz_object: SSZObject, domain: B256) -> B256 {
    SigningData {
        object_root: ssz_object.tree_hash_root(),
        domain,
    }
    .tree_hash_root()
}

pub fn compute_shuffled_index(
    index: usize,
    index_count: usize,
    seed: B256,
) -> anyhow::Result<usize> {
    ensure!(index < index_count, "Index must be less than index_count");
    let mut index = index;
    for round in 0..SHUFFLE_ROUND_COUNT {
        let seed_with_round = [seed.as_slice(), &round.to_le_bytes()].concat();
        let pivot = bytes_to_int64(&hash(&seed_with_round)[..]) % index_count as u64;

        let flip = (pivot as usize + (index_count - index)) % index_count;
        let position = max(index, flip);
        let seed_with_position =
            [seed_with_round.as_slice(), &(position / 256).to_le_bytes()].concat();
        let source = hash(&seed_with_position);
        let byte = source[(position % 256) / 8];
        let bit = (byte >> (position % 8)) % 2;

        index = if bit == 1 { flip } else { index };
    }
    Ok(index)
}

fn bytes_to_int64(slice: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&slice[0..8]);
    u64::from_le_bytes(bytes)
}

/// Return from ``indices`` a random index sampled by effective balance
pub fn compute_proposer_index(
    state: BeaconState,
    indices: &[u64],
    seed: B256,
) -> anyhow::Result<u64> {
    ensure!(!indices.is_empty(), "Index must be less than index_count");

    let mut i: usize = 0;
    let total = indices.len();

    loop {
        let candidate_index = indices[compute_shuffled_index(i % total, total, seed)?];

        let seed_with_index = [seed.as_slice(), &(i / 32).to_le_bytes()].concat();
        let hash = hash(&seed_with_index);
        let random_byte = hash[i % 32];

        let effective_balance = state.validators[candidate_index as usize].effective_balance;

        if (effective_balance * MAX_RANDOM_BYTE) >= (MAX_EFFECTIVE_BALANCE * random_byte as u64) {
            return Ok(candidate_index);
        }

        i += 1;
    }
}

/// Return the committee corresponding to ``indices``, ``seed``, ``index``, and committee ``count``.
pub fn compute_committee(
    indices: &[u64],
    seed: B256,
    index: u64,
    count: u64,
) -> anyhow::Result<Vec<u64>> {
    let start = (indices.len() as u64 * index) / count;
    let end = (indices.len() as u64 * (index + 1)) / count;
    (start..end)
        .map(|i| {
            let shuffled_index = compute_shuffled_index(i as usize, indices.len(), seed)?;
            indices
                .get(shuffled_index)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("Index out of bounds: {}", shuffled_index))
        })
        .collect::<anyhow::Result<Vec<u64>>>()
}

pub fn is_shuffling_stable(slot: u64) -> bool {
    slot % SLOTS_PER_EPOCH != 0
}

/// Return the epoch number at ``slot``.
pub fn compute_epoch_at_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_EPOCH
}

/// Return the start slot of ``epoch``.
pub fn compute_start_slot_at_epoch(epoch: u64) -> u64 {
    epoch * SLOTS_PER_EPOCH
}

/// Return the epoch during which validator activations and exits initiated in ``epoch`` take
/// effect.
pub fn compute_activation_exit_epoch(epoch: u64) -> u64 {
    epoch + 1 + MAX_SEED_LOOKAHEAD
}

/// Return the domain for the ``domain_type`` and ``fork_version``
pub fn compute_domain(
    domain_type: B32,
    fork_version: Option<B32>,
    genesis_validators_root: Option<B256>,
) -> anyhow::Result<B256> {
    let fork_data = ForkData {
        current_version: fork_version.unwrap_or_default(),
        genesis_validators_root: genesis_validators_root.unwrap_or_default(),
    };
    let fork_data_root = fork_data.compute_fork_data_root();
    let domain_bytes = [&domain_type.0, &fork_data_root.0[..28]].concat();
    Ok(B256::from_slice(&domain_bytes))
}
