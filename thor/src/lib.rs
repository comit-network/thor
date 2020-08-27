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
mod transaction;

pub use ::bitcoin;
pub use protocols::create::{BuildFundingPSBT, SignFundingPSBT};

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
use protocols::{close, create, recycle, update};
use signature::decrypt;

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

#[async_trait::async_trait]
pub trait NewAddress {
    async fn new_address(&self) -> anyhow::Result<Address>;
}

#[async_trait::async_trait]
pub trait BroadcastSignedTransaction {
    async fn broadcast_signed_transaction(&self, transaction: Transaction) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
pub trait SendMessage {
    async fn send_message(&mut self, message: Message) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
pub trait ReceiveMessage {
    async fn receive_message(&mut self) -> anyhow::Result<Message>;
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
    ) -> anyhow::Result<Self>
    where
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction + NewAddress,
        T: SendMessage + ReceiveMessage,
    {
        let final_address = wallet.new_address().await?;
        let state0 = create::State0::new(fund_amount, time_lock, final_address);

        let msg0_self = state0.next_message();
        transport.send_message(Message::Create0(msg0_self)).await?;

        let msg0_other = map_err(transport.receive_message().await?.into_create0())?;
        let state1 = state0.receive(msg0_other, wallet).await?;

        let msg1_self = state1.next_message();
        transport.send_message(Message::Create1(msg1_self)).await?;

        let msg1_other = map_err(transport.receive_message().await?.into_create1())?;
        let state2 = state1.receive(msg1_other)?;

        let msg2_self = state2.next_message();
        transport.send_message(Message::Create2(msg2_self)).await?;

        let msg2_other = map_err(transport.receive_message().await?.into_create2())?;
        let state3 = state2.receive(msg2_other)?;

        let msg3_self = state3.next_message();
        transport.send_message(Message::Create3(msg3_self)).await?;

        let msg3_other = map_err(transport.receive_message().await?.into_create3())?;
        let state_4 = state3.receive(msg3_other)?;

        let msg4_self = state_4.next_message();
        transport.send_message(Message::Create4(msg4_self)).await?;

        let msg4_other = map_err(transport.receive_message().await?.into_create4())?;
        let state5 = state_4.receive(msg4_other)?;

        let msg5_self = state5.next_message(wallet).await?;
        transport.send_message(Message::Create5(msg5_self)).await?;

        let msg5_other = map_err(transport.receive_message().await?.into_create5())?;

        let (channel, transaction) = state5.receive(msg5_other, wallet).await?;

        wallet.broadcast_signed_transaction(transaction).await?;

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
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let state0 = update::State0::new(self.clone(), new_balance, time_lock);

        let msg0_self = state0.compose();
        transport.send_message(Message::Update0(msg0_self)).await?;

        let msg0_other = map_err(transport.receive_message().await?.into_update0())?;
        let state1 = state0.interpret(msg0_other)?;

        let msg1_self = state1.compose();
        transport.send_message(Message::Update1(msg1_self)).await?;

        let msg1_other = map_err(transport.receive_message().await?.into_update1())?;
        let state2 = state1.interpret(msg1_other)?;

        let msg2_self = state2.compose();
        transport.send_message(Message::Update2(msg2_self)).await?;

        let msg2_other = map_err(transport.receive_message().await?.into_update2())?;
        let state3 = state2.interpret(msg2_other)?;

        let msg3_self = state3.compose();
        transport.send_message(Message::Update3(msg3_self)).await?;

        let msg3_other = map_err(transport.receive_message().await?.into_update3())?;
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
    pub async fn close<T, W>(&mut self, transport: &mut T, wallet: &W) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        let state0 = close::State0::new(&self);

        let msg0_self = state0.compose()?;
        transport.send_message(Message::Close0(msg0_self)).await?;

        let msg0_other = map_err(transport.receive_message().await?.into_close0())?;
        let close_transaction = state0.interpret(msg0_other)?;

        wallet
            .broadcast_signed_transaction(close_transaction)
            .await?;

        Ok(())
    }

    pub async fn force_close<W>(&mut self, wallet: &W) -> anyhow::Result<()>
    where
        W: NewAddress + BroadcastSignedTransaction,
    {
        let commit_transaction = self
            .current_state
            .signed_TX_c(&self.x_self, &self.X_other)?;
        wallet
            .broadcast_signed_transaction(commit_transaction)
            .await?;

        let split_transaction = self.current_state.signed_TX_s.clone();
        wallet
            .broadcast_signed_transaction(split_transaction.clone().into())
            .await?;

        Ok(())
    }

    /// Punish the counterparty for publishing a revoked commit transaction.
    ///
    /// This effectively closes the channel, as all of the channel's funds go to
    /// our final address.
    pub async fn punish<W>(
        &self,
        wallet: &W,
        old_commit_transaction: Transaction,
    ) -> anyhow::Result<()>
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
            .await?;

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
    pub fn latest_revoked_signed_TX_c(&self) -> anyhow::Result<Option<Transaction>> {
        self.revoked_states
            .last()
            .map(|state| state.signed_TX_c(self.x_self.clone(), self.X_other.clone()))
            .transpose()
    }

    /// Recycle a channel.
    ///
    /// Create a new funding transaction using a previous funding transaction as
    /// input This is useless in this state :]
    pub async fn recycle<T, W>(self, transport: &mut T, wallet: &W) -> anyhow::Result<Self>
    where
        W: BroadcastSignedTransaction,
        T: SendMessage + ReceiveMessage,
    {
        // Re-use timelock, final addresses, balance, ownership keys
        let final_address_self = self.final_address_self;
        let final_address_other = self.final_address_other;
        let time_lock = self.current_state.time_lock();
        let balance = self.current_state.balance;
        let x_self = self.x_self;
        let X_other = self.X_other;

        let state0 = recycle::State0::new(
            time_lock,
            final_address_self,
            final_address_other,
            balance,
            self.TX_f_body,
            x_self,
            X_other,
        )?;

        let msg0_self = state0.next_message();
        transport.send_message(Message::Recycle0(msg0_self)).await?;

        let msg0_other = map_err(transport.receive_message().await?.into_recycle0())?;
        let state1 = state0.receive(msg0_other)?;

        let msg1_self = state1.next_message();
        transport.send_message(Message::Recycle1(msg1_self)).await?;

        let msg1_other = map_err(transport.receive_message().await?.into_recycle1())?;
        let state2 = state1.receive(msg1_other)?;

        let msg2_self = state2.next_message();
        transport.send_message(Message::Recycle2(msg2_self)).await?;

        let msg2_other = map_err(transport.receive_message().await?.into_recycle2())?;
        let state3 = state2.receive(msg2_other)?;

        let msg3_self = state3.next_message().await?;
        transport.send_message(Message::Recycle3(msg3_self)).await?;

        let msg3_other = map_err(transport.receive_message().await?.into_recycle3())?;

        let (channel, transaction) = state3.receive(msg3_other)?;

        wallet.broadcast_signed_transaction(transaction).await?;

        Ok(channel)
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
    ) -> anyhow::Result<Transaction> {
        let sig_self = self.TX_c.sign(x_self);
        let sig_other = decrypt(self.y_self.clone().into(), self.encsig_TX_c_other.clone());

        let signed_TX_c = self
            .TX_c
            .clone()
            .add_signatures((x_self.public(), sig_self), (X_other.clone(), sig_other))?;

        Ok(signed_TX_c)
    }

    pub fn time_lock(&self) -> u32 {
        self.TX_c.time_lock()
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
    Recycle0(recycle::Message0),
    Recycle1(recycle::Message1),
    Recycle2(recycle::Message2),
    Recycle3(recycle::Message3),
}

#[derive(Debug, thiserror::Error)]
#[error("expected message of type {expected_type}, got {received:?}")]
pub struct UnexpecteMessage {
    expected_type: String,
    received: Message,
}

impl UnexpecteMessage {
    pub fn new<T>(received: Message) -> Self {
        let expected_type = std::any::type_name::<T>();

        Self {
            expected_type: expected_type.to_string(),
            received,
        }
    }
}

fn map_err<T>(res: Result<T, Message>) -> Result<T, UnexpecteMessage> {
    res.map_err(UnexpecteMessage::new::<T>)
}
