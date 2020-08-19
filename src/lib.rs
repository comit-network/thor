#![allow(non_snake_case)]

pub mod create;
mod keys;
pub mod punish;
mod signature;
mod transaction;
pub mod update;

use crate::{
    keys::{OwnershipPublicKey, PublishingKeyPair, RevocationKeyPair},
    transaction::{CommitTransaction, SplitTransaction},
};
use bitcoin::Amount;
use ecdsa_fun::adaptor::EncryptedSignature;
use keys::{PublishingPublicKey, RevocationPublicKey, RevocationSecretKey};

#[derive(Clone)]
pub struct ChannelState {
    TX_c: CommitTransaction,
    /// Encrypted signature sent to the counterparty. If the
    /// counterparty decrypts it with their own `PublishingSecretKey`
    /// and uses it to sign and broadcast `TX_c`, we will be able to
    /// extract their `PublishingSecretKey` by using
    /// `recover_decryption_key`. If said `TX_c` was already revoked,
    /// we can use it with the `RevocationSecretKey` to punish them.
    encsig_TX_c_self: EncryptedSignature,
    /// Encrypted signature received from the counterparty. It can be
    /// decrypted using our `PublishingSecretkey` and used to sign
    /// `TX_c`. Keep in mind, that publishing a revoked `TX_c` will
    /// allow the counterparty to punish us.
    encsig_TX_c_other: EncryptedSignature,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    /// Signed split transaction.
    signed_TX_s: SplitTransaction,
}

#[derive(Clone)]
pub struct RevokedState {
    channel_state: ChannelState,
    r_other: RevocationSecretKey,
}

impl RevokedState {
    /// Add signatures to the `CommitTransaction`. Publishing the resulting
    /// transaction is punishable by the counterparty, as they can recover the
    /// `PublishingSecretkey` from it and they already know the
    /// `RevocationSecretKey`, since this state has already been revoked.
    pub fn signed_TX_c(
        &self,
        x_self: keys::OwnershipKeyPair,
        X_other: OwnershipPublicKey,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let sig_TX_c_other = signature::decrypt(
            self.channel_state.y_self.clone().into(),
            self.channel_state.encsig_TX_c_other.clone(),
        );
        let sig_TX_c_self = self.channel_state.TX_c.sign(&x_self);

        let signed_TX_c = self
            .channel_state
            .TX_c
            .clone()
            .add_signatures((x_self.public(), sig_TX_c_self), (X_other, sig_TX_c_other))?;

        Ok(signed_TX_c)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChannelBalance {
    a: (Amount, OwnershipPublicKey),
    b: (Amount, OwnershipPublicKey),
}
