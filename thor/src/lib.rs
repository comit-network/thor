#![warn(
    unused_extern_crates,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::fallible_impl_from,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::dbg_macro
)]
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

#[cfg(feature = "serde")]
pub(crate) mod serde;

pub mod channel;
mod keys;
mod signature;
mod transaction;

pub use ::bitcoin;
pub use channel::Channel;
pub use keys::{PtlcPoint, PtlcSecret};

use crate::{
    channel::protocols::{close, create, splice, update},
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    signature::decrypt,
    transaction::{
        ptlc::{RedeemTransaction, RefundTransaction},
        CommitTransaction, FundingTransaction, SplitTransaction,
    },
};
use ::serde::{Deserialize, Serialize};
use anyhow::Result;
use bitcoin::{Address, Amount, Transaction, TxOut, Txid};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use enum_as_inner::EnumAsInner;
use std::convert::TryFrom;

#[cfg(feature = "serde")]
use bitcoin::util::amount::serde::as_sat;

// TODO: We should handle fees dynamically

// TODO: Have it as an `Amount` instead
/// Flat fee used for all transactions involved in the protocol, in satoshi.
pub const TX_FEE: u64 = 10_000;

#[async_trait::async_trait]
pub trait MedianTime {
    async fn median_time(&self) -> Result<u32>;
}

#[async_trait::async_trait]
pub trait GetRawTransaction {
    async fn get_raw_transaction(&self, txid: Txid) -> Result<Transaction>;
}

#[derive(Clone, Debug)]
pub enum Splice {
    /// Useful if the other party wants to splice in or out
    None,
    In(Amount),
    Out(TxOut),
}

#[allow(clippy::large_enum_variant)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, EnumAsInner)]
pub(crate) enum ChannelState {
    Standard(StandardChannelState),
    WithPtlc {
        inner: StandardChannelState,
        ptlc: Ptlc,
        tx_ptlc_redeem: RedeemTransaction,
        tx_ptlc_refund: RefundTransaction,
        encsig_tx_ptlc_redeem_funder: EncryptedSignature,
        sig_tx_ptlc_redeem_redeemer: Signature,
        sig_tx_ptlc_refund_funder: Signature,
        sig_tx_ptlc_refund_redeemer: Signature,
    },
}

impl From<ChannelState> for StandardChannelState {
    fn from(from: ChannelState) -> Self {
        match from {
            ChannelState::Standard(state) | ChannelState::WithPtlc { inner: state, .. } => state,
        }
    }
}

impl AsRef<StandardChannelState> for ChannelState {
    fn as_ref(&self) -> &StandardChannelState {
        match self {
            ChannelState::Standard(state) | ChannelState::WithPtlc { inner: state, .. } => state,
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct StandardChannelState {
    /// Proportion of the coins in the channel that currently belong to either
    /// party. To actually claim these coins one or more transactions will have
    /// to be submitted to the blockchain, so in practice the balance will see a
    /// reduction to pay for transaction fees.
    balance: Balance,
    tx_c: CommitTransaction,
    /// Encrypted signature received from the counterparty. It can be decrypted
    /// using our `PublishingSecretKey` and used to sign `tx_c`. Keep in mind,
    /// that publishing a revoked `tx_c` will allow the counterparty to punish
    /// us.
    encsig_tx_c_other: EncryptedSignature,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    /// Signed `SplitTransaction`.
    signed_tx_s: SplitTransaction,
}

impl StandardChannelState {
    fn signed_tx_c(
        &self,
        tx_f: &FundingTransaction,
        x_self: &OwnershipKeyPair,
        X_other: &OwnershipPublicKey,
    ) -> Result<Transaction> {
        let sig_self = self.tx_c.sign(x_self);
        let sig_other = decrypt(self.y_self.clone().into(), self.encsig_tx_c_other.clone());

        let signed_tx_c = self.tx_c.clone().add_signatures(
            tx_f,
            (x_self.public(), sig_self),
            (X_other.clone(), sig_other),
        )?;

        Ok(signed_tx_c)
    }

    pub fn time_lock(&self) -> u32 {
        self.tx_c.time_lock()
    }

    pub fn encsign_tx_c_self(&self, x_self: &OwnershipKeyPair) -> EncryptedSignature {
        self.tx_c.encsign(x_self, self.Y_other.clone())
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub(crate) struct RevokedState {
    channel_state: ChannelState,
    r_other: RevocationSecretKey,
}

impl RevokedState {
    /// Add signatures to the `CommitTransaction`. Publishing the resulting
    /// transaction is punishable by the counterparty, as they can recover the
    /// `PublishingSecretKey` from it and they already know the
    /// `RevocationSecretKey`, since this state has already been revoked.
    #[cfg(test)]
    fn signed_tx_c(
        &self,
        tx_f: &FundingTransaction,
        x_self: OwnershipKeyPair,
        X_other: OwnershipPublicKey,
    ) -> Result<Transaction> {
        StandardChannelState::from(self.channel_state.clone()).signed_tx_c(tx_f, &x_self, &X_other)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Balance {
    #[cfg_attr(feature = "serde", serde(with = "as_sat"))]
    pub ours: Amount,
    #[cfg_attr(feature = "serde", serde(with = "as_sat"))]
    pub theirs: Amount,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub enum SplitOutput {
    Ptlc(Ptlc),
    Balance {
        #[cfg_attr(feature = "serde", serde(with = "as_sat"))]
        amount: Amount,
        address: Address,
    },
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Ptlc {
    #[cfg_attr(feature = "serde", serde(with = "as_sat"))]
    amount: Amount,
    X_funder: OwnershipPublicKey,
    X_redeemer: OwnershipPublicKey,
    role: Role,
    refund_time_lock: u32,
}

impl Ptlc {
    pub fn point(&self) -> PtlcPoint {
        match &self.role {
            Role::Alice { secret } => secret.point(),
            Role::Bob { point } => point.clone(),
        }
    }
}

/// Role in an atomic swap.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, EnumAsInner)]
pub enum Role {
    Alice { secret: PtlcSecret },
    Bob { point: PtlcPoint },
}

impl SplitOutput {
    pub fn amount(&self) -> Amount {
        match self {
            SplitOutput::Ptlc(Ptlc { amount, .. }) => *amount,
            SplitOutput::Balance { amount, .. } => *amount,
        }
    }
}

/// All possible messages that can be sent between two parties using this
/// library.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, EnumAsInner)]
pub enum Message {
    Create0(create::Message0),
    Create1(create::Message1),
    Create2(create::Message2),
    Create3(create::Message3),
    Create4(create::Message4),
    Create5(create::Message5),
    Update0(update::ShareKeys),
    UpdatePtlcFunder(update::SignaturesPtlcFunder),
    UpdatePtlcRedeemer(update::SignaturesPtlcRedeemer),
    Update1(update::ShareSplitSignature),
    Update2(update::ShareCommitEncryptedSignature),
    Update3(update::RevealRevocationSecretKey),
    Secret(PtlcSecret),
    Close0(close::Message0),
    Splice0(splice::Message0),
    Splice1(splice::Message1),
    Splice2(splice::Message2),
    Splice3(splice::Message3),
}

#[derive(Debug, thiserror::Error)]
#[error("expected message of type {expected_type}, got {received:?}")]
pub struct UnexpectedMessage {
    expected_type: String,
    received: Message,
}

impl UnexpectedMessage {
    pub fn new<T>(received: Message) -> Self {
        let expected_type = std::any::type_name::<T>();

        Self {
            expected_type: expected_type.to_string(),
            received,
        }
    }
}

impl From<create::Message0> for Message {
    fn from(m: create::Message0) -> Self {
        Message::Create0(m)
    }
}

impl TryFrom<Message> for create::Message0 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Create0(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Create0".to_string(),
                received: m,
            }),
        }
    }
}

impl From<create::Message1> for Message {
    fn from(m: create::Message1) -> Self {
        Message::Create1(m)
    }
}

impl TryFrom<Message> for create::Message1 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Create1(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Create1".to_string(),
                received: m,
            }),
        }
    }
}

impl From<create::Message2> for Message {
    fn from(m: create::Message2) -> Self {
        Message::Create2(m)
    }
}

impl TryFrom<Message> for create::Message2 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Create2(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Create2".to_string(),
                received: m,
            }),
        }
    }
}

impl From<create::Message3> for Message {
    fn from(m: create::Message3) -> Self {
        Message::Create3(m)
    }
}

impl TryFrom<Message> for create::Message3 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Create3(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Create3".to_string(),
                received: m,
            }),
        }
    }
}

impl From<create::Message4> for Message {
    fn from(m: create::Message4) -> Self {
        Message::Create4(m)
    }
}

impl TryFrom<Message> for create::Message4 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Create4(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Create4".to_string(),
                received: m,
            }),
        }
    }
}

impl From<create::Message5> for Message {
    fn from(m: create::Message5) -> Self {
        Message::Create5(m)
    }
}

impl TryFrom<Message> for create::Message5 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Create5(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Create5".to_string(),
                received: m,
            }),
        }
    }
}

impl From<update::ShareKeys> for Message {
    fn from(m: update::ShareKeys) -> Self {
        Message::Update0(m)
    }
}

impl TryFrom<Message> for update::ShareKeys {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Update0(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Update0".to_string(),
                received: m,
            }),
        }
    }
}

impl From<update::SignaturesPtlcFunder> for Message {
    fn from(m: update::SignaturesPtlcFunder) -> Self {
        Message::UpdatePtlcFunder(m)
    }
}

impl TryFrom<Message> for update::SignaturesPtlcFunder {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::UpdatePtlcFunder(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "UpdatePtlcFunder".to_string(),
                received: m,
            }),
        }
    }
}

impl From<update::SignaturesPtlcRedeemer> for Message {
    fn from(m: update::SignaturesPtlcRedeemer) -> Self {
        Message::UpdatePtlcRedeemer(m)
    }
}

impl TryFrom<Message> for update::SignaturesPtlcRedeemer {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::UpdatePtlcRedeemer(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "UpdatePtlcRedeemer".to_string(),
                received: m,
            }),
        }
    }
}

impl From<update::ShareSplitSignature> for Message {
    fn from(m: update::ShareSplitSignature) -> Self {
        Message::Update1(m)
    }
}

impl TryFrom<Message> for update::ShareSplitSignature {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Update1(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Update1".to_string(),
                received: m,
            }),
        }
    }
}

impl From<update::ShareCommitEncryptedSignature> for Message {
    fn from(m: update::ShareCommitEncryptedSignature) -> Self {
        Message::Update2(m)
    }
}

impl TryFrom<Message> for update::ShareCommitEncryptedSignature {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Update2(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Update2".to_string(),
                received: m,
            }),
        }
    }
}

impl From<update::RevealRevocationSecretKey> for Message {
    fn from(m: update::RevealRevocationSecretKey) -> Self {
        Message::Update3(m)
    }
}

impl TryFrom<Message> for update::RevealRevocationSecretKey {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Update3(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Update3".to_string(),
                received: m,
            }),
        }
    }
}

impl From<PtlcSecret> for Message {
    fn from(m: PtlcSecret) -> Self {
        Message::Secret(m)
    }
}

impl TryFrom<Message> for PtlcSecret {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Secret(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Secret".to_string(),
                received: m,
            }),
        }
    }
}

impl From<close::Message0> for Message {
    fn from(m: close::Message0) -> Self {
        Message::Close0(m)
    }
}

impl TryFrom<Message> for close::Message0 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Close0(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Close0".to_string(),
                received: m,
            }),
        }
    }
}

impl From<splice::Message0> for Message {
    fn from(m: splice::Message0) -> Self {
        Message::Splice0(m)
    }
}

impl TryFrom<Message> for splice::Message0 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Splice0(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Splice0".to_string(),
                received: m,
            }),
        }
    }
}

impl From<splice::Message1> for Message {
    fn from(m: splice::Message1) -> Self {
        Message::Splice1(m)
    }
}

impl TryFrom<Message> for splice::Message1 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Splice1(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Splice1".to_string(),
                received: m,
            }),
        }
    }
}

impl From<splice::Message2> for Message {
    fn from(m: splice::Message2) -> Self {
        Message::Splice2(m)
    }
}

impl TryFrom<Message> for splice::Message2 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Splice2(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Splice2".to_string(),
                received: m,
            }),
        }
    }
}

impl From<splice::Message3> for Message {
    fn from(m: splice::Message3) -> Self {
        Message::Splice3(m)
    }
}

impl TryFrom<Message> for splice::Message3 {
    type Error = UnexpectedMessage;

    fn try_from(m: Message) -> Result<Self, Self::Error> {
        match m {
            Message::Splice3(m) => Ok(m),
            _ => Err(UnexpectedMessage {
                expected_type: "Splice3".to_string(),
                received: m,
            }),
        }
    }
}
