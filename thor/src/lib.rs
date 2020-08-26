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

mod keys;
mod protocols;
mod signature;
mod traits;
mod transaction;

pub use ::bitcoin;
pub use traits::{
    BroadcastSignedTransaction, BuildFundingPSBT, NewAddress, ReceiveMessage, SendMessage,
    SignFundingPSBT,
};

use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    protocols::punish::punish,
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
};
use bitcoin::{Address, Amount, Transaction, Txid};
use ecdsa_fun::adaptor::EncryptedSignature;
use enum_as_inner::EnumAsInner;
use protocols::{close, create, update};
use signature::decrypt;

pub type Result<T> = std::result::Result<T, Error>;

// TODO: We should handle fees dynamically

/// Flat fee used for all transactions involved in the protocol, in satoshi.
pub const TX_FEE: u64 = 10_000;

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct Channel {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f_body: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
}

impl Channel {
    /// Create a channel.
    ///
    /// The `fund_amount` represents how much Bitcoin either party will
    /// contribute to the channel. This means both parties contribute the same
    /// amount.
    ///
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `transport` they provide, allowing the parties to communicate
    /// with each other.
    pub async fn create<T, W>(
        transport: &mut T,
        wallet: &W,
        fund_amount: Amount,
        time_lock: u32,
    ) -> Result<Self>
    where
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction + NewAddress,
        T: SendMessage + ReceiveMessage,
    {
        let final_address = wallet
            .new_address()
            .await
            .map_err(|err| Error::Wallet(format!("Could not get new address: {}", err)))?;
        let state0 = create::State0::new(fund_amount, time_lock, final_address);

        let msg0_self = state0.next_message();
        transport
            .send_message(Message::Create0(msg0_self))
            .await
            .map_err(Error::transport)?;

        let msg0_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_create0(),
        )?;
        let state1 = state0.receive(msg0_other, wallet).await?;

        let msg1_self = state1.next_message();
        transport
            .send_message(Message::Create1(msg1_self))
            .await
            .map_err(Error::transport)?;

        let msg1_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_create1(),
        )?;
        let state2 = state1.receive(msg1_other)?;

        let msg2_self = state2.next_message();
        transport
            .send_message(Message::Create2(msg2_self))
            .await
            .map_err(Error::transport)?;

        let msg2_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_create2(),
        )?;
        let state3 = state2.receive(msg2_other)?;

        let msg3_self = state3.next_message();
        transport
            .send_message(Message::Create3(msg3_self))
            .await
            .map_err(Error::transport)?;

        let msg3_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_create3(),
        )?;
        let state_4 = state3.receive(msg3_other)?;

        let msg4_self = state_4.next_message();
        transport
            .send_message(Message::Create4(msg4_self))
            .await
            .map_err(Error::transport)?;

        let msg4_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_create4(),
        )?;
        let state5 = state_4.receive(msg4_other)?;

        let msg5_self = state5.next_message(wallet).await?;
        transport
            .send_message(Message::Create5(msg5_self))
            .await
            .map_err(Error::transport)?;

        let msg5_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_create5(),
        )?;

        let (channel, transaction) = state5.receive(msg5_other, wallet).await?;

        wallet
            .broadcast_signed_transaction(transaction)
            .await
            .map_err(Error::wallet)?;

        Ok(channel)
    }

    /// Update the distribution of coins in the channel.
    ///
    /// It assumes that the counterparty has already agreed to update the
    /// channel with the `new_balance` and the same `timelock` and will call
    /// the same API (or an equivalent one).
    ///
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `transport` they provide, allowing the parties to communicate
    /// with each other.
    pub async fn update<T>(
        &mut self,
        transport: &mut T,
        new_balance: Balance,
        time_lock: u32,
    ) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let state0 = update::State0::new(self.clone(), new_balance, time_lock);

        let msg0_self = state0.compose();
        transport
            .send_message(Message::Update0(msg0_self))
            .await
            .map_err(Error::transport)?;

        let msg0_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_update0(),
        )?;
        let state1 = state0.interpret(msg0_other)?;

        let msg1_self = state1.compose();
        transport
            .send_message(Message::Update1(msg1_self))
            .await
            .map_err(Error::transport)?;

        let msg1_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_update1(),
        )?;
        let state2 = state1.interpret(msg1_other)?;

        let msg2_self = state2.compose();
        transport
            .send_message(Message::Update2(msg2_self))
            .await
            .map_err(Error::transport)?;

        let msg2_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_update2(),
        )?;
        let state3 = state2.interpret(msg2_other)?;

        let msg3_self = state3.compose();
        transport
            .send_message(Message::Update3(msg3_self))
            .await
            .map_err(Error::transport)?;

        let msg3_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_update3(),
        )?;
        let updated_channel = state3.interpret(msg3_other)?;

        *self = updated_channel;

        Ok(())
    }

    /// Close the channel collaboratively.
    ///
    /// It assumes that the counterparty has already agreed to close the channel
    /// and will call the same API (or an equivalent one).
    ///
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `transport` they provide, allowing the parties to communicate
    /// with each other.
    pub async fn close<T, W>(&mut self, transport: &mut T, wallet: &W) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        let state0 = close::State0::new(&self);

        let msg0_self = state0.compose()?;
        transport
            .send_message(Message::Close0(msg0_self))
            .await
            .map_err(Error::transport)?;

        let msg0_other = map_msg_err(
            transport
                .receive_message()
                .await
                .map_err(Error::transport)?
                .into_close0(),
        )?;
        let close_transaction = state0.interpret(msg0_other)?;

        wallet
            .broadcast_signed_transaction(close_transaction)
            .await
            .map_err(Error::wallet)?;

        Ok(())
    }

    pub async fn force_close<W>(&mut self, wallet: &W) -> Result<()>
    where
        W: NewAddress + BroadcastSignedTransaction,
    {
        let commit_transaction = self
            .current_state
            .signed_TX_c(&self.x_self, &self.X_other)?;
        wallet
            .broadcast_signed_transaction(commit_transaction)
            .await
            .map_err(Error::wallet)?;

        let split_transaction = self.current_state.signed_TX_s.clone();
        wallet
            .broadcast_signed_transaction(split_transaction.clone().into())
            .await
            .map_err(Error::wallet)?;

        Ok(())
    }

    /// Punish the counterparty for publishing a revoked commit transaction.
    ///
    /// This effectively closes the channel, as all of the channel's funds go to
    /// our final address.
    pub async fn punish<W>(&self, wallet: &W, old_commit_transaction: Transaction) -> Result<()>
    where
        W: BroadcastSignedTransaction,
    {
        let punish_transaction = punish(
            &self.x_self,
            &self.revoked_states,
            self.final_address_self.clone(),
            old_commit_transaction,
        )?;

        wallet
            .broadcast_signed_transaction(punish_transaction.into())
            .await
            .map_err(Error::wallet)?;

        Ok(())
    }

    pub fn balance(&self) -> Balance {
        self.current_state.balance
    }

    pub fn TX_f_txid(&self) -> Txid {
        self.TX_f_body.txid()
    }

    /// Retrieve the signed `CommitTransaction` of the state that was revoked
    /// during the last channel update.
    pub fn latest_revoked_signed_TX_c(&self) -> Result<Option<Transaction>> {
        self.revoked_states
            .last()
            .map(|state| state.signed_TX_c(self.x_self.clone(), self.X_other.clone()))
            .transpose()
    }
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct ChannelState {
    /// Proportion of the coins in the channel that currently belong to either
    /// party. To actually claim these coins one or more transactions will have
    /// to be submitted to the blockchain, so in practice the balance will see a
    /// reduction to pay for transaction fees.
    balance: Balance,
    TX_c: CommitTransaction,
    /// Encrypted signature sent to the counterparty. If the counterparty
    /// decrypts it with their own `PublishingSecretKey` and uses it to sign and
    /// broadcast `TX_c`, we will be able to extract their `PublishingSecretKey`
    /// by using `recover_decryption_key`. If said `TX_c` was already revoked,
    /// we can use it with the `RevocationSecretKey` to punish them.
    encsig_TX_c_self: EncryptedSignature,
    /// Encrypted signature received from the counterparty. It can be decrypted
    /// using our `PublishingSecretkey` and used to sign `TX_c`. Keep in mind,
    /// that publishing a revoked `TX_c` will allow the counterparty to punish
    /// us.
    encsig_TX_c_other: EncryptedSignature,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    /// Signed split transaction.
    signed_TX_s: SplitTransaction,
}

impl ChannelState {
    pub fn signed_TX_c(
        &self,
        x_self: &OwnershipKeyPair,
        X_other: &OwnershipPublicKey,
    ) -> Result<Transaction> {
        let sig_self = self.TX_c.sign(x_self);
        let sig_other = decrypt(self.y_self.clone().into(), self.encsig_TX_c_other.clone());

        let signed_TX_c = self
            .TX_c
            .clone()
            .add_signatures((x_self.public(), sig_self), (X_other.clone(), sig_other))?;

        Ok(signed_TX_c)
    }
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
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
    ) -> Result<bitcoin::Transaction> {
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

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Balance {
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
    pub ours: Amount,
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
    pub theirs: Amount,
}

/// All possible messages that can be sent between two parties using this
/// library.
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, EnumAsInner)]
pub enum Message {
    Create0(create::Message0),
    Create1(create::Message1),
    Create2(create::Message2),
    Create3(create::Message3),
    Create4(create::Message4),
    Create5(create::Message5),
    Update0(update::ShareKeys),
    Update1(update::ShareSplitSignature),
    Update2(update::ShareCommitEncryptedSignature),
    Update3(update::RevealRevocationSecretKey),
    Close0(close::Message0),
}

#[derive(Debug, thiserror::Error)]
#[error("expected message of type {expected_type}, got {received:?}")]
pub struct UnexpectedMessage {
    expected_type: String,
    received: Message,
}

impl Error {
    pub fn unexpected_message<T>(received: Message) -> Self {
        let expected_type = std::any::type_name::<T>();

        Error::UnexpectedMessage(Box::new(UnexpectedMessage {
            expected_type: expected_type.to_string(),
            received,
        }))
    }

    pub fn transport<E>(error: E) -> Self
    where
        E: std::fmt::Display,
    {
        Self::Transport(error.to_string())
    }

    pub fn wallet<E>(error: E) -> Self
    where
        E: std::fmt::Display,
    {
        Self::Wallet(error.to_string())
    }
}

fn map_msg_err<T>(res: std::result::Result<T, Message>) -> Result<T> {
    res.map_err(Error::unexpected_message::<T>)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Transaction: ")]
    Transaction(#[from] crate::transaction::Error),
    #[error("Keys: ")]
    Keys(#[from] crate::keys::Error),
    #[error("Failed to verify close transaction signature sent by counterparty: ")]
    CloseTransactionSignature(crate::transaction::Error),
    #[error("Timelocks are not equal")]
    IncompatibleTimeLocks,
    #[error("Failed to build funding transaction: ")]
    BuildFundTransaction(crate::transaction::Error),
    #[error("Failed to verify sig_TX_s sent by counterparty: ")]
    VerifyReceivedSigTXs(crate::transaction::Error),
    #[error("Failed to verify encsig_TX_c sent by counterparty: ")]
    VerifyReceivedEncSigTXc(crate::transaction::Error),
    #[error("Transaction cannot be punished")]
    NotOldCommitTransaction,
    #[error("{0}")]
    UnexpectedMessage(Box<UnexpectedMessage>),
    #[error("Transport: {0}")]
    Transport(String),
    #[error("Wallet: {0}")]
    Wallet(String),
    #[error("{0}")]
    Custom(String),
}
