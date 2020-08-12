use crate::{
    keys::{OwnershipPublicKey, PublishingPublicKey},
    transaction::{CommitTransaction, SplitTransaction},
};
use bitcoin::{hashes::Hash, SigHash};
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    nonce, Signature, ECDSA,
};
use rand::prelude::ThreadRng;
use sha2::Sha256;

#[derive(Debug, thiserror::Error)]
#[error("signature is invalid")]
pub struct InvalidSignature;

pub fn verify_sig(
    public_key: OwnershipPublicKey,
    TX_s: &SplitTransaction,
    signature: &Signature,
) -> Result<(), InvalidSignature> {
    let ecdsa = ECDSA::verify_only();

    if ecdsa.verify(&public_key.into(), &TX_s.digest().into_inner(), &signature) {
        Ok(())
    } else {
        Err(InvalidSignature)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("presignature is invalid")]
pub struct InvalidPresignature;

pub fn preverify_sig(
    verification_key: OwnershipPublicKey,
    encryption_key: PublishingPublicKey,
    TX_c: &CommitTransaction,
    presignature: EncryptedSignature,
) -> Result<(), InvalidPresignature> {
    let adaptor = Adaptor::<Sha256, _>::new(nonce::from_global_rng::<Sha256, ThreadRng>());

    if adaptor.verify_encrypted_signature(
        &verification_key.into(),
        &encryption_key.into(),
        &TX_c.digest().into_inner(),
        &presignature,
    ) {
        Ok(())
    } else {
        Err(InvalidPresignature)
    }
}
