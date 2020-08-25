use crate::keys::{OwnershipPublicKey, PublishingPublicKey, PublishingSecretKey};
use bitcoin::hashes::Hash;
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    nonce::Deterministic,
    Signature, ECDSA,
};

use bitcoin::SigHash;
use sha2::Sha256;

#[derive(Debug, thiserror::Error)]
#[error("signature is invalid")]
pub struct InvalidSignature;

pub fn verify_sig(
    verification_key: OwnershipPublicKey,
    transaction_sighash: &SigHash,
    signature: &Signature,
) -> Result<(), InvalidSignature> {
    let ecdsa = ECDSA::verify_only();

    if ecdsa.verify(
        &verification_key.into(),
        &transaction_sighash.into_inner(),
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
    transaction_sighash: &SigHash,
    encsig: &EncryptedSignature,
) -> Result<(), InvalidEncryptedSignature> {
    let adaptor = Adaptor::<Sha256, Deterministic<Sha256>>::default();

    if adaptor.verify_encrypted_signature(
        &verification_key.into(),
        &encryption_key.into(),
        &transaction_sighash.into_inner(),
        &encsig,
    ) {
        Ok(())
    } else {
        Err(InvalidEncryptedSignature)
    }
}

#[allow(dead_code)]
pub fn decrypt(decryption_key: PublishingSecretKey, encsig: EncryptedSignature) -> Signature {
    let adaptor = Adaptor::<Sha256, Deterministic<Sha256>>::default();

    adaptor.decrypt_signature(&decryption_key.into(), encsig)
}
