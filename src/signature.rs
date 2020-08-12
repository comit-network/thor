use crate::{
    keys::{OwnershipPublicKey, PublishingPublicKey},
    transaction::{CommitTransaction, SplitTransaction},
};
use bitcoin::{hashes::Hash, SigHash};
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    Signature, ECDSA,
};

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
    let adaptor = Adaptor::from_tag(b"my-tag");

    if adaptor.verify_encrypted_signature(
        &verification_key.into(),
        &encryption_key.into(),
        &TX_c.digest().into_inner(),
        presignature,
    ) {
        Ok(())
    } else {
        Err(InvalidPresignature)
    }
}
