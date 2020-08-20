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
    /// on the `network` they provide, allowing Alice to communicate with
    /// Bob.
    pub async fn create_alice<N, W>(
        network: &mut N,
        wallet: &W,
        fund_amount: Amount,
        time_lock: u32,
    ) -> anyhow::Result<Self>
    where
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction,
        N: SendMessage + ReceiveMessage,
    {
        let alice0 = create::Alice0::new(fund_amount, time_lock);

        let message0_alice = alice0.next_message();
        network
            .send_message(Message::CreateMessage0(message0_alice))
            .await?;

        let message0_bob = match network.receive_message().await? {
            Message::CreateMessage0(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let alice1 = alice0.receive(message0_bob, wallet).await.unwrap();

        let message1_alice = alice1.next_message();
        network
            .send_message(Message::CreateMessage1(message1_alice))
            .await?;

        let message1_bob = match network.receive_message().await? {
            Message::CreateMessage1(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let alice2 = alice1.receive(message1_bob).unwrap();

        let message2_alice = alice2.next_message();
        network
            .send_message(Message::CreateMessage2(message2_alice))
            .await?;

        let message2_bob = match network.receive_message().await? {
            Message::CreateMessage2(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let alice3 = alice2.receive(message2_bob).unwrap();

        Self::create(network, wallet, alice3).await
    }

    /// Create a channel in the role of Bob.
    ///
    /// The `fund_amount` represents how much Bitcoin Bob will contribute to
    /// the channel. Alice will contribute the _same_ amount as Bob.
    ///
    /// Consumers should implement the traits `SendMessage` and `ReceiveMessage`
    /// on the `network` they provide, allowing Bob to communicate with Alice.
    pub async fn create_bob<N, W>(
        network: &mut N,
        wallet: &W,
        fund_amount: Amount,
        time_lock: u32,
    ) -> anyhow::Result<Self>
    where
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction,
        N: SendMessage + ReceiveMessage,
    {
        let bob0 = create::Bob0::new(fund_amount, time_lock);

        let message0_bob = bob0.next_message();
        network
            .send_message(Message::CreateMessage0(message0_bob))
            .await?;

        let message0_alice = match network.receive_message().await? {
            Message::CreateMessage0(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let bob1 = bob0.receive(message0_alice, wallet).await.unwrap();

        let message1_bob = bob1.next_message();
        network
            .send_message(Message::CreateMessage1(message1_bob))
            .await?;

        let message1_alice = match network.receive_message().await? {
            Message::CreateMessage1(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let bob2 = bob1.receive(message1_alice).unwrap();

        let message2_bob = bob2.next_message();
        network
            .send_message(Message::CreateMessage2(message2_bob))
            .await?;

        let message2_alice = match network.receive_message().await? {
            Message::CreateMessage2(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let bob3 = bob2.receive(message2_alice).unwrap();

        Self::create(network, wallet, bob3).await
    }

    async fn create<W, N>(
        network: &mut N,
        wallet: &W,
        party3: create::Party3,
    ) -> anyhow::Result<Self>
    where
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction,
        N: SendMessage + ReceiveMessage,
    {
        let message3_self = party3.next_message();
        network
            .send_message(Message::CreateMessage3(message3_self))
            .await?;

        let message3_other = match network.receive_message().await? {
            Message::CreateMessage3(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let party4 = party3.receive(message3_other).unwrap();

        let message4_self = party4.next_message();
        network
            .send_message(Message::CreateMessage4(message4_self))
            .await?;

        let message4_other = match network.receive_message().await? {
            Message::CreateMessage4(message) => message,
            _ => anyhow::bail!("wrong message"),
        };
        let party5 = party4.receive(message4_other).unwrap();

        let message5_self = party5.next_message(wallet).await.unwrap();
        network
            .send_message(Message::CreateMessage5(message5_self))
            .await?;
        let message5_other = match network.receive_message().await? {
            Message::CreateMessage5(message) => message,
            _ => anyhow::bail!("wrong message"),
        };

        let party6 = party5.receive(message5_other, wallet).await.unwrap();

        wallet
            .broadcast_signed_transaction(party6.signed_TX_f)
            .await?;

        Ok(Self {
            x_self: party6.x_self,
            X_other: party6.X_other,
            TX_f_body: party6.TX_f_body,
            current_state: ChannelState {
                TX_c: party6.TX_c,
                encsig_TX_c_self: party6.encsig_TX_c_self,
                encsig_TX_c_other: party6.encsig_TX_c_other,
                r_self: party6.r_self,
                R_other: party6.R_other,
                y_self: party6.y_self,
                Y_other: party6.Y_other,
                signed_TX_s: party6.signed_TX_s,
            },
            revoked_states: Vec::new(),
        })
    }

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
pub enum Message {
    CreateMessage0(create::Message0),
    CreateMessage1(create::Message1),
    CreateMessage2(create::Message2),
    CreateMessage3(create::Message3),
    CreateMessage4(create::Message4),
    CreateMessage5(create::Message5),
}
