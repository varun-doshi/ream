use crate::{
    attestation_data::AttestationData, deneb::beacon_state::BeaconState,
    fork_choice::helpers::constants::DOMAIN_BEACON_ATTESTER,
    indexed_attestation::IndexedAttestation, misc::compute_signing_root,
};

/// Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
pub fn is_slashable_attestation_data(data_1: &AttestationData, data_2: &AttestationData) -> bool {
    (data_1 != data_2 && data_1.target.epoch == data_2.target.epoch)
        || (data_1.source.epoch < data_2.source.epoch && data_2.target.epoch < data_1.target.epoch)
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
    // Verify indices are sorted and unique
    if indices.is_empty() || !is_sorted_and_unique(&indices) {
        return false;
    }

    // Collect public keys of attesting validators
    let pubkeys: Vec<_> = indices
        .iter()
        .filter_map(|&i| state.validators.get(i).map(|v| v.pubkey.clone()))
        .collect();

    // Compute domain and signing root
    let domain = match state.get_domain(
        DOMAIN_BEACON_ATTESTER,
        Some(indexed_attestation.data.target.epoch),
    ) {
        Ok(domain) => domain,
        Err(_) => return false, // Return false if domain retrieval fails
    };

    let sig =
        blst::min_pk::Signature::from_bytes(&indexed_attestation.signature.signature).unwrap();
    let signing_root = compute_signing_root(&indexed_attestation.data, domain);

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

fn is_sorted_and_unique(indices: &[usize]) -> bool {
    indices.windows(2).all(|w| w[0] < w[1])
}
