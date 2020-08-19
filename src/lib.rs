#![allow(non_snake_case)]

pub mod create;
mod keys;
pub mod punish;
mod signature;
mod transaction;
pub mod update;

use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, RevocationKeyPair},
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
};
use anyhow::bail;
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

#[derive(Clone, Debug, PartialEq)]
pub struct SplitOutputs {
    a: (Amount, OwnershipPublicKey),
    b: (Amount, OwnershipPublicKey),
}

pub struct Channel {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    TX_f_body: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LocalBalance {
    pub ours: Amount,
    pub theirs: Amount,
}

impl Channel {
    pub fn new(party: create::Party6) -> Self {
        Self {
            x_self: party.x_self,
            X_other: party.X_other,
            TX_f_body: party.TX_f_body,
            current_state: ChannelState {
                TX_c: party.TX_c,
                encsig_TX_c_self: party.encsig_TX_c_self,
                encsig_TX_c_other: party.encsig_TX_c_other,
                r_self: party.r_self,
                R_other: party.R_other,
                y_self: party.y_self,
                Y_other: party.Y_other,
                signed_TX_s: party.signed_TX_s,
            },
            revoked_states: Vec::new(),
        }
    }

    pub fn balance(&self) -> anyhow::Result<LocalBalance> {
        let outputs = self.current_state.signed_TX_s.outputs();

        match outputs {
            SplitOutputs {
                a: (ours, X_a),
                b: (theirs, X_b),
            } if X_a == self.x_self.public() && X_b == self.X_other => {
                Ok(LocalBalance { ours, theirs })
            }
            SplitOutputs {
                a: (theirs, X_a),
                b: (ours, X_b),
            } if X_a == self.X_other && X_b == self.x_self.public() => {
                Ok(LocalBalance { ours, theirs })
            }
            _ => bail!("split transaction does not pay to X_self and X_other"),
        }
    }
}
