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
use ecdsa_fun::{
    adaptor::EncryptedSignature,
    fun::{Point, Scalar},
};
use enum_as_inner::EnumAsInner;
use protocols::{close, create, update};
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
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `transport` they provide, allowing the parties to communicate
    /// with each other.
    pub async fn create<T, W>(
        transport: &mut T,
        wallet: &W,
        balance: Balance,
        time_lock: u32,
    ) -> anyhow::Result<Self>
    where
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction + NewAddress,
        T: SendMessage + ReceiveMessage,
    {
        let final_address = wallet.new_address().await?;
        let state0 = create::State0::new(balance, time_lock, final_address);

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
    /// channel with the same balance and `timelock` and will call the same API
    /// (or an equivalent one).
    ///
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `transport` they provide, allowing the parties to communicate
    /// with each other.
    pub async fn update<T>(
        &mut self,
        transport: &mut T,
        Balance { ours, theirs }: Balance,
        time_lock: u32,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let split_output_self = SplitOutput::Balance {
            amount: ours,
            address: self.final_address_self.clone(),
        };

        let split_output_other = SplitOutput::Balance {
            amount: theirs,
            address: self.final_address_other.clone(),
        };

        self._update(
            transport,
            vec![split_output_self, split_output_other],
            time_lock,
        )
        .await
    }

    /// Perform an atomic swap with a thor channel as beta ledger in the
    /// role of Alice.
    pub async fn add_ptlc_alice<T>(
        &mut self,
        _transport: &mut T,
        _new_split_outputs: Vec<SplitOutput>,
        _encryption_secret_key: Scalar,
        _alpha_absolute_expiry: u32,
        _TX_s_time_lock: u32,
        _ptlc_redeem_time_lock: u32,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        // TODO: Think about how to handle the three expiries.

        // 1. Construct and sign ptlc_refund and ptlc_redeem transactions (this requires
        // building TX_c and TX_s too).
        // 2. Send signatures to Bob.
        // 3. Caller must convince Bob that the alpha asset is funded (outside of this
        // function).
        // 4. Receive Bob's signature for ptlc_refund and encsignature for ptlc_redeem.
        // 5. Run channel update protocol to add PTLC output.
        // 6. Send encryption_secret_key to Bob (who will use it to redeem alpha asset).
        // 7. Attempt to perform a channel update to add PTLC output to Alice's balance
        // output. If Bob doesn't respond, force close and publish ptlc_redeem. If he
        // does respond, carry out the update and feel free to forget the
        // encryption_secret_key.

        todo!()
    }

    /// Perform an atomic swap with a thor channel as beta ledger in the
    /// role of Bob.
    pub async fn add_ptlc_bob<T>(
        &mut self,
        _transport: &mut T,
        _new_split_outputs: Vec<SplitOutput>,
        _encryption_public_key: Point,
        _alpha_absolute_expiry: u32,
        _TX_s_time_lock: u32,
        _ptlc_redeem_time_lock: u32,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        // 1. Construct and sign ptlc_refund and construct and encsign ptlc_redeem
        // transactions using the encryption_public_key (this requires building TX_c and
        // TX_s too).
        // 2. Receive Alice's signatures for ptlc_refund and for ptlc_redeem.
        // 3. Alice must convince the caller that the alpha asset is funded (outside of
        // this function).
        // 4. Send signature and encsignature from step 1 to Alice.
        // 5. Run channel update protocol to add PTLC output.
        // 6. Wait for Alice to send over the encryption_secret_key. If she doesn't,
        // force close and publish ptlc_refund as soon as possible - Alice will have
        // time to publish ptlc_redeem after we force close, but if she does the caller
        // will learn the secret and will be able to redeem beta asset. If she does, use
        // it to redeem beta asset.
        // 7. Perform a channel update to add PTLC output to Alice's balance output.

        todo!()
    }

    pub async fn _update<T>(
        &mut self,
        transport: &mut T,
        new_split_outputs: Vec<SplitOutput>,
        time_lock: u32,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let state0 = update::State0::new(self.clone(), new_split_outputs, time_lock);

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
        // We ignore PTLC outputs because it's hard to determine who owns them. Maybe
        // this method is not that useful.
        self.current_state.split_outputs.iter().fold(
            Balance {
                ours: Amount::ZERO,
                theirs: Amount::ZERO,
            },
            |acc, output| match output {
                SplitOutput::Balance { amount, address } if address == &self.final_address_self => {
                    Balance {
                        ours: acc.ours + *amount,
                        theirs: acc.theirs,
                    }
                }
                SplitOutput::Balance { amount, address }
                    if address == &self.final_address_other =>
                {
                    Balance {
                        ours: acc.ours,
                        theirs: acc.theirs + *amount,
                    }
                }
                _ => acc,
            },
        )
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
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct ChannelState {
    // TODO: Rework this docstring
    /// Proportion of the coins in the channel that currently belong to either
    /// party. To actually claim these coins one or more transactions will have
    /// to be submitted to the blockchain, so in practice the balance will see a
    /// reduction to pay for transaction fees.
    split_outputs: Vec<SplitOutput>,
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

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, Clone)]
pub enum SplitOutput {
    Ptlc {
        #[cfg_attr(
            feature = "serde",
            serde(with = "bitcoin::util::amount::serde::as_sat")
        )]
        amount: Amount,
        X_funder: OwnershipPublicKey,
        X_redeemer: OwnershipPublicKey,
    },
    Balance {
        #[cfg_attr(
            feature = "serde",
            serde(with = "bitcoin::util::amount::serde::as_sat")
        )]
        amount: Amount,
        address: Address,
    },
}

impl SplitOutput {
    pub fn amount(&self) -> Amount {
        match self {
            SplitOutput::Ptlc { amount, .. } => *amount,
            SplitOutput::Balance { amount, .. } => *amount,
        }
    }
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
