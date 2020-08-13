#![allow(non_snake_case, unreachable_code)]

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
    TX_s: SplitTransaction,
}

#[derive(Clone)]
pub struct RevokedState {
    channel_state: ChannelState,
    r_other: RevocationSecretKey,
}

#[derive(Clone)]
pub struct ChannelBalance {
    a: (Amount, OwnershipPublicKey),
    b: (Amount, OwnershipPublicKey),
}
