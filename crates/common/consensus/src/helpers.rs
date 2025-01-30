use std::cmp;

use alloy_primitives::B256;

use crate::{
    checkpoint::Checkpoint,
    deneb::beacon_state::BeaconState,
    fork_choice::{
        helpers::constants::{
            DOMAIN_BEACON_ATTESTER, EFFECTIVE_BALANCE_INCREMENT, PROPOSER_SCORE_BOOST,
            SLOTS_PER_EPOCH,
        },
        store::Store,
    },
    indexed_attestation::IndexedAttestation,
    misc::{compute_epoch_at_slot, compute_signing_root},
    pubkey::PubKey,
    validator::Validator,
};

pub fn is_active_validator(validator: &Validator, epoch: u64) -> bool {
    validator.activation_eligibility_epoch <= epoch && epoch < validator.exit_epoch
}

pub fn get_total_balance(state: &BeaconState, indices: Vec<u64>) -> u64 {
    let sum = indices
        .iter()
        .map(|&index| {
            state
                .validators
                .get(index as usize)
                .unwrap()
                .effective_balance
        })
        .sum();
    cmp::max(EFFECTIVE_BALANCE_INCREMENT, sum)
}

pub fn get_total_active_balance(state: BeaconState) -> u64 {
    get_total_balance(
        &state,
        state.get_active_validator_indices(state.get_current_epoch()),
    )
}

pub fn calculate_committee_fraction(state: BeaconState, committee_percent: u64) -> u64 {
    let committee_weight = get_total_active_balance(state) / SLOTS_PER_EPOCH;
    (committee_weight * committee_percent) / 100
}

pub fn get_proposer_score(store: Store) -> u64 {
    let justified_checkpoint_state = store
        .checkpoint_states
        .get(&store.justified_checkpoint)
        .unwrap();
    let committee_weight =
        get_total_active_balance(justified_checkpoint_state.clone()) / SLOTS_PER_EPOCH;
    (committee_weight * PROPOSER_SCORE_BOOST) / 100
}

pub fn get_weight(store: Store, root: B256) -> u64 {
    let state = &store.checkpoint_states[&store.justified_checkpoint];

    let unslashed_and_active_indices: Vec<u64> = state
        .get_active_validator_indices(state.get_current_epoch())
        .into_iter()
        .filter(|&i| !state.validators[i as usize].slashed)
        .collect();

    let attestation_score: u64 = unslashed_and_active_indices
        .iter()
        .filter(|&&i| {
            store.latest_messages.contains_key(&i)
                && !store.equivocating_indices.contains(&i)
                && store.get_ancestor(store.latest_messages[&i].root, store.blocks[&root].slot)
                    == root
        })
        .map(|&i| state.validators[i as usize].effective_balance)
        .sum::<u64>();

    if store.proposer_boost_root == B256::ZERO {
        return attestation_score;
    }

    let mut proposer_score: u64 = 0;
    if store.get_ancestor(store.proposer_boost_root, store.blocks[&root].slot) == root {
        proposer_score = get_proposer_score(store);
    }

    attestation_score + proposer_score
}

pub fn get_voting_source(store: &Store, block_root: B256) -> Checkpoint {
    let block = &store.blocks[&block_root];

    let current_epoch = store.get_current_slot();
    let block_epoch = compute_epoch_at_slot(block.slot);

    if current_epoch > block_epoch {
        store.unrealized_justifications[&block_root]
    } else {
        let head_state = &store.block_states[&block_root];
        head_state.current_justified_checkpoint
    }
}

pub fn is_valid_indexed_attestation(
    state: &BeaconState,
    indexed_attestation: &IndexedAttestation,
) -> bool {
    let indices: Vec<usize> = indexed_attestation
        .attesting_indices
        .iter()
        .map(|&i| i as usize)
        .collect();

    if indices.is_empty() || !is_sorted_and_unique(&indices) {
        return false;
    }

    let pubkeys: Vec<&PubKey> = indices
        .iter()
        .map(|&i| &state.validators.get(i).unwrap().pubkey)
        .collect();

    let domain = match state.get_domain(
        DOMAIN_BEACON_ATTESTER,
        Some(indexed_attestation.data.target.epoch),
    ) {
        Ok(domain) => domain,
        Err(_) => return false,
    };

    let signing_root = compute_signing_root(&indexed_attestation.data, domain);

    let sig =
        blst::min_pk::Signature::from_bytes(&indexed_attestation.signature.signature).unwrap();

    let publickeys: Vec<blst::min_pk::PublicKey> = pubkeys
        .iter()
        .filter_map(|key| blst::min_pk::PublicKey::from_bytes(&key.inner).ok())
        .collect();

    let verification_result = sig.fast_aggregate_verify(
        true,
        signing_root.as_ref(),
        domain.as_ref(),
        publickeys.iter().collect::<Vec<_>>().as_slice(),
    );

    matches!(verification_result, blst::BLST_ERROR::BLST_SUCCESS)
}

// Helper function to check if a slice is sorted and contains unique elements
fn is_sorted_and_unique(indices: &[usize]) -> bool {
    indices.windows(2).all(|w| w[0] < w[1])
}
