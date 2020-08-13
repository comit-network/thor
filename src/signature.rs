use crate::{
    keys::{OwnershipPublicKey, PublishingPublicKey},
    transaction::{CommitTransaction, SplitTransaction},
};
use bitcoin::{hashes::Hash, SigHash};
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    nonce::{self, Deterministic},
    Signature, ECDSA,
};
use rand::prelude::ThreadRng;
use sha2::Sha256;

#[derive(Debug, thiserror::Error)]
#[error("signature is invalid")]
pub struct InvalidSignature;

pub fn verify_sig(
    verification_key: OwnershipPublicKey,
    TX_s: &SplitTransaction,
    signature: &Signature,
) -> Result<(), InvalidSignature> {
    let ecdsa = ECDSA::verify_only();

    if ecdsa.verify(
        &verification_key.into(),
        &TX_s.digest().into_inner(),
        &signature,
    ) {
        Ok(())
    } else {
        Err(InvalidSignature)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("encrypted signature is invalid")]
pub struct InvalidEncryptedSignature;

pub fn verify_encsig(
    verification_key: OwnershipPublicKey,
    encryption_key: PublishingPublicKey,
    TX_c: &CommitTransaction,
    encsig: &EncryptedSignature,
) -> Result<(), InvalidEncryptedSignature> {
    let adaptor = Adaptor::<Sha256, Deterministic<Sha256>>::default();

    if adaptor.verify_encrypted_signature(
        &verification_key.into(),
        &encryption_key.into(),
        &TX_c.digest().into_inner(),
        &encsig,
    ) {
        Ok(())
    } else {
        Err(InvalidEncryptedSignature)
    }
}
