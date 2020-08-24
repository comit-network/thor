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

mod keys;
pub mod protocols;
mod signature;
mod transaction;

#[cfg(feature = "serde")]
pub(crate) mod serde;

use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    protocols::create::{BuildFundingPSBT, SignFundingPSBT},
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
};
use anyhow::bail;
use bitcoin::{Address, Amount, Transaction};
use ecdsa_fun::adaptor::EncryptedSignature;
use enum_as_inner::EnumAsInner;
use protocols::{close, create, update};
use signature::decrypt;

// TODO: We should handle fees dynamically

/// Flat fee used for all transactions involved in the protocol. Satoshi is the
/// unit used.
pub const TX_FEE: u64 = 10_000;

#[derive(Clone, Debug)]
pub struct Channel {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    pub TX_f_body: FundingTransaction,
    pub current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
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
    /// Create a channel in the role of Alice.
    ///
    /// The `fund_amount` represents how much Bitcoin Alice will contribute to
    /// the channel. Bob will contribute the _same_ amount as Alice.
    ///
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `transport` they provide, allowing Alice to communicate with
    /// Bob.
    pub async fn create_alice<T, W>(
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
        let alice0 = create::Alice0::new(fund_amount, time_lock, final_address);

        let msg0_alice = alice0.next_message();
        transport.send_message(Message::Create0(msg0_alice)).await?;

        let msg0_bob = map_err(transport.receive_message().await?.into_create0())?;
        let alice1 = alice0.receive(msg0_bob, wallet).await?;

        let msg1_alice = alice1.next_message();
        transport.send_message(Message::Create1(msg1_alice)).await?;

        let msg1_bob = map_err(transport.receive_message().await?.into_create1())?;
        let alice2 = alice1.receive(msg1_bob)?;

        let msg2_alice = alice2.next_message();
        transport.send_message(Message::Create2(msg2_alice)).await?;

        let msg2_bob = map_err(transport.receive_message().await?.into_create2())?;

        let alice3 = alice2.receive(msg2_bob)?;

        Self::create(transport, wallet, alice3).await
    }

    /// Create a channel in the role of Bob.
    ///
    /// The `fund_amount` represents how much Bitcoin Bob will contribute to
    /// the channel. Alice will contribute the _same_ amount as Bob.
    ///
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `transport` they provide, allowing Bob to communicate with Alice.
    pub async fn create_bob<T, W>(
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
        let bob0 = create::Bob0::new(fund_amount, time_lock, final_address);

        let msg0_bob = bob0.next_message();
        transport.send_message(Message::Create0(msg0_bob)).await?;

        let msg0_alice = map_err(transport.receive_message().await?.into_create0())?;
        let bob1 = bob0.receive(msg0_alice, wallet).await?;

        let msg1_bob = bob1.next_message();
        transport.send_message(Message::Create1(msg1_bob)).await?;

        let msg1_alice = map_err(transport.receive_message().await?.into_create1())?;
        let bob2 = bob1.receive(msg1_alice)?;

        let msg2_bob = bob2.next_message();
        transport.send_message(Message::Create2(msg2_bob)).await?;

        let msg2_alice = map_err(transport.receive_message().await?.into_create2())?;
        let bob3 = bob2.receive(msg2_alice)?;

        Self::create(transport, wallet, bob3).await
    }

    async fn create<W, T>(
        transport: &mut T,
        wallet: &W,
        state3: create::Party3,
    ) -> anyhow::Result<Self>
    where
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction,
        T: SendMessage + ReceiveMessage,
    {
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

    pub async fn update_alice<T>(
        &mut self,
        transport: &mut T,
        new_balance: Balance,
        time_lock: u32,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let alice0 = update::Alice0::new(self.clone(), new_balance, time_lock);

        let msg0_alice = alice0.compose();
        transport.send_message(Message::Update0(msg0_alice)).await?;

        let msg0_bob = map_err(transport.receive_message().await?.into_update0())?;
        let alice1 = alice0.interpret(msg0_bob)?;

        self.update(transport, alice1).await
    }

    pub async fn update_bob<T>(
        &mut self,
        transport: &mut T,
        new_balance: Balance,
        time_lock: u32,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let bob0 = update::Bob0::new(self.clone(), new_balance, time_lock);

        let msg0_bob = bob0.compose();
        transport.send_message(Message::Update0(msg0_bob)).await?;

        let msg0_alice = map_err(transport.receive_message().await?.into_update0())?;
        let bob1 = bob0.interpret(msg0_alice)?;

        self.update(transport, bob1).await
    }

    async fn update<T>(&mut self, transport: &mut T, state1: update::State1) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
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

    /// Close the channel collaboratively. It assumes that the counterparty has
    /// already agreed to close the channel and will call the same API (or an
    /// equivalent one).
    pub async fn close<T, W>(&mut self, transport: &mut T, wallet: &W) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        let state0 = close::State0::new(&self);

        let msg0_self = state0.compose();
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

    pub fn balance(&self) -> anyhow::Result<Balance> {
        let outputs = self.current_state.signed_TX_s.outputs();

        match outputs {
            SplitOutputs {
                a: (ours, address_a),
                b: (theirs, address_b),
            } if address_a == self.final_address_self && address_b == self.final_address_other => {
                Ok(Balance { ours, theirs })
            }
            SplitOutputs {
                a: (theirs, address_a),
                b: (ours, address_b),
            } if address_a == self.final_address_other && address_b == self.final_address_self => {
                Ok(Balance { ours, theirs })
            }
            _ => bail!("split transaction does not pay to expected addresses"),
        }
    }

    /// Retrieve the signed `CommitTransaction` of the state that was revoked
    /// during the last channel update.
    pub fn latest_revoked_signed_TX_c(&self) -> anyhow::Result<Option<Transaction>> {
        self.revoked_states
            .last()
            .map(|state| state.signed_TX_c(self.x_self.clone(), self.X_other.clone()))
            .transpose()
    }
}

#[derive(Clone, Debug)]
pub struct ChannelState {
    pub TX_c: CommitTransaction,
    /// Encrypted signature sent to the counterparty. If the
    /// counterparty decrypts it with their own `PublishingSecretKey`
    /// and uses it to sign and broadcast `TX_c`, we will be able to
    /// extract their `PublishingSecretKey` by using
    /// `recover_decryption_key`. If said `TX_c` was already revoked,
    /// we can use it with the `RevocationSecretKey` to punish them.
    pub encsig_TX_c_self: EncryptedSignature,
    /// Encrypted signature received from the counterparty. It can be
    /// decrypted using our `PublishingSecretkey` and used to sign
    /// `TX_c`. Keep in mind, that publishing a revoked `TX_c` will
    /// allow the counterparty to punish us.
    pub encsig_TX_c_other: EncryptedSignature,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    /// Signed split transaction.
    pub signed_TX_s: SplitTransaction,
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
}

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

#[derive(Clone, Debug, PartialEq)]
pub struct SplitOutputs {
    a: (Amount, Address),
    b: (Amount, Address),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Balance {
    pub ours: Amount,
    pub theirs: Amount,
}

#[async_trait::async_trait]
pub trait NewAddress {
    async fn new_address(&self) -> anyhow::Result<Address>;
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
