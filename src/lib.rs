#![allow(non_snake_case)]

pub mod create;
mod keys;
pub mod punish;
mod signature;
mod transaction;
pub mod update;

use crate::{
    create::{BuildFundingPSBT, SignFundingPSBT},
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
};
use anyhow::bail;
use bitcoin::{Amount, Transaction};
use ecdsa_fun::adaptor::EncryptedSignature;

#[derive(Clone)]
pub struct Channel {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
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
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction,
        T: SendMessage + ReceiveMessage,
    {
        let alice0 = create::Alice0::new(fund_amount, time_lock);

        let message0_alice = alice0.next_message();
        transport
            .send_message(Message::CreateMessage0(message0_alice))
            .await?;

        let message0_bob = match transport.receive_message().await? {
            Message::CreateMessage0(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message0>(message)),
        };
        let alice1 = alice0.receive(message0_bob, wallet).await?;

        let message1_alice = alice1.next_message();
        transport
            .send_message(Message::CreateMessage1(message1_alice))
            .await?;

        let message1_bob = match transport.receive_message().await? {
            Message::CreateMessage1(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message1>(message)),
        };
        let alice2 = alice1.receive(message1_bob)?;

        let message2_alice = alice2.next_message();
        transport
            .send_message(Message::CreateMessage2(message2_alice))
            .await?;

        let message2_bob = match transport.receive_message().await? {
            Message::CreateMessage2(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message2>(message)),
        };
        let alice3 = alice2.receive(message2_bob)?;

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
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction,
        T: SendMessage + ReceiveMessage,
    {
        let bob0 = create::Bob0::new(fund_amount, time_lock);

        let message0_bob = bob0.next_message();
        transport
            .send_message(Message::CreateMessage0(message0_bob))
            .await?;

        let message0_alice = match transport.receive_message().await? {
            Message::CreateMessage0(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message0>(message)),
        };
        let bob1 = bob0.receive(message0_alice, wallet).await?;

        let message1_bob = bob1.next_message();
        transport
            .send_message(Message::CreateMessage1(message1_bob))
            .await?;

        let message1_alice = match transport.receive_message().await? {
            Message::CreateMessage1(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message1>(message)),
        };
        let bob2 = bob1.receive(message1_alice)?;

        let message2_bob = bob2.next_message();
        transport
            .send_message(Message::CreateMessage2(message2_bob))
            .await?;

        let message2_alice = match transport.receive_message().await? {
            Message::CreateMessage2(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message2>(message)),
        };
        let bob3 = bob2.receive(message2_alice)?;

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
        let message3_self = state3.next_message();
        transport
            .send_message(Message::CreateMessage3(message3_self))
            .await?;

        let message3_other = match transport.receive_message().await? {
            Message::CreateMessage3(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message3>(message)),
        };
        let state_4 = state3.receive(message3_other)?;

        let message4_self = state_4.next_message();
        transport
            .send_message(Message::CreateMessage4(message4_self))
            .await?;

        let message4_other = match transport.receive_message().await? {
            Message::CreateMessage4(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message4>(message)),
        };
        let state5 = state_4.receive(message4_other)?;

        let message5_self = state5.next_message(wallet).await?;
        transport
            .send_message(Message::CreateMessage5(message5_self))
            .await?;
        let message5_other = match transport.receive_message().await? {
            Message::CreateMessage5(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<create::Message5>(message)),
        };

        let (channel, transaction) = state5.receive(message5_other, wallet).await?;

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

        let message0_alice = alice0.compose();
        transport
            .send_message(Message::UpdateMessage0(message0_alice))
            .await?;

        let message0_bob = match transport.receive_message().await? {
            Message::UpdateMessage0(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<update::ShareKeys>(message)),
        };
        let alice1 = alice0.interpret(message0_bob)?;

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

        let message0_bob = bob0.compose();
        transport
            .send_message(Message::UpdateMessage0(message0_bob))
            .await?;

        let message0_alice = match transport.receive_message().await? {
            Message::UpdateMessage0(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<update::ShareKeys>(message)),
        };
        let bob1 = bob0.interpret(message0_alice)?;

        self.update(transport, bob1).await
    }

    pub async fn update<T>(
        &mut self,
        transport: &mut T,
        state1: update::State1,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let message1_self = state1.compose();
        transport
            .send_message(Message::UpdateMessage1(message1_self))
            .await?;

        let message1_other = match transport.receive_message().await? {
            Message::UpdateMessage1(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<update::ShareSplitSignature>(
                message
            )),
        };
        let state2 = state1.interpret(message1_other)?;

        let message2_self = state2.compose();
        transport
            .send_message(Message::UpdateMessage2(message2_self))
            .await?;

        let message2_other = match transport.receive_message().await? {
            Message::UpdateMessage2(message) => message,
            message => anyhow::bail!(
                UnexpecteMessage::new::<update::ShareCommitEncryptedSignature>(message)
            ),
        };
        let state3 = state2.interpret(message2_other)?;

        let message3_self = state3.compose();
        transport
            .send_message(Message::UpdateMessage3(message3_self))
            .await?;

        let message3_other = match transport.receive_message().await? {
            Message::UpdateMessage3(message) => message,
            message => anyhow::bail!(UnexpecteMessage::new::<update::RevealRevocationSecretKey>(
                message
            )),
        };
        let updated_channel = state3.interpret(message3_other)?;

        *self = updated_channel;

        Ok(())
    }

    pub fn balance(&self) -> anyhow::Result<Balance> {
        let outputs = self.current_state.signed_TX_s.outputs();

        match outputs {
            SplitOutputs {
                a: (ours, X_a),
                b: (theirs, X_b),
            } if X_a == self.x_self.public() && X_b == self.X_other => Ok(Balance { ours, theirs }),
            SplitOutputs {
                a: (theirs, X_a),
                b: (ours, X_b),
            } if X_a == self.X_other && X_b == self.x_self.public() => Ok(Balance { ours, theirs }),
            _ => bail!("split transaction does not pay to X_self and X_other"),
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

#[derive(Clone)]
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
pub struct SplitOutputs {
    a: (Amount, OwnershipPublicKey),
    b: (Amount, OwnershipPublicKey),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Balance {
    pub ours: Amount,
    pub theirs: Amount,
}

/// All possible messages that can be sent between two parties using this
/// library.
#[derive(Debug)]
pub enum Message {
    CreateMessage0(create::Message0),
    CreateMessage1(create::Message1),
    CreateMessage2(create::Message2),
    CreateMessage3(create::Message3),
    CreateMessage4(create::Message4),
    CreateMessage5(create::Message5),
    UpdateMessage0(update::ShareKeys),
    UpdateMessage1(update::ShareSplitSignature),
    UpdateMessage2(update::ShareCommitEncryptedSignature),
    UpdateMessage3(update::RevealRevocationSecretKey),
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
