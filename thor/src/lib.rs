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
pub use keys::{PtlcPoint, PtlcSecret};
pub use protocols::create::{BuildFundingPsbt, SignFundingPsbt};

use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    protocols::{close, create, punish::punish, splice, update},
    signature::decrypt,
    transaction::{
        CommitTransaction, FundingTransaction, RedeemTransaction, RefundTransaction,
        SplitTransaction,
    },
};
use ::serde::{Deserialize, Serialize};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use bitcoin::{Address, Amount, Transaction, TxOut, Txid};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use enum_as_inner::EnumAsInner;
use futures::{future::Either, pin_mut, Future};
use genawaiter::sync::Gen;
use std::convert::{TryFrom, TryInto};

// TODO: We should handle fees dynamically

// TODO: Have it as an `Amount` instead
/// Flat fee used for all transactions involved in the protocol, in satoshi.
pub const TX_FEE: u64 = 10_000;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Channel {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    tx_f_body: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
}

#[async_trait]
pub trait NewAddress {
    async fn new_address(&self) -> Result<Address>;
}

#[async_trait]
pub trait BroadcastSignedTransaction {
    async fn broadcast_signed_transaction(&self, transaction: Transaction) -> Result<()>;
}

#[async_trait]
pub trait SendMessage {
    async fn send_message(&mut self, message: Message) -> Result<()>;
}

#[async_trait]
pub trait ReceiveMessage {
    async fn receive_message(&mut self) -> Result<Message>;
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
    ) -> Result<Self>
    where
        T: SendMessage + ReceiveMessage,
        W: BuildFundingPsbt + SignFundingPsbt + BroadcastSignedTransaction + NewAddress,
    {
        let final_address = wallet.new_address().await?;
        let state = create::State0::new(balance, time_lock, final_address);

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response, wallet).await?;

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response)?;

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response)?;

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response)?;

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response)?;

        transport
            .send_message(state.compose(wallet).await?.into())
            .await?;
        let response = transport.receive_message().await?.try_into()?;
        let (channel, transaction) = state.interpret(response, wallet).await?;

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
    pub async fn update_balance<T>(
        &mut self,
        transport: &mut T,
        Balance { ours, theirs }: Balance,
        time_lock: u32,
    ) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        let out_ours = self.split_balance_output_ours(ours);
        let out_theirs = self.split_balance_output_theirs(theirs);

        self.update(transport, vec![out_ours, out_theirs], time_lock)
            .await
    }

    fn split_balance_output_ours(&self, amount: Amount) -> SplitOutput {
        SplitOutput::Balance {
            amount,
            address: self.final_address_self.clone(),
        }
    }

    fn split_balance_output_theirs(&self, amount: Amount) -> SplitOutput {
        SplitOutput::Balance {
            amount,
            address: self.final_address_other.clone(),
        }
    }

    /// Perform an atomic swap with a thor channel as beta ledger in the
    /// role of Alice.
    #[allow(clippy::too_many_arguments)]
    pub async fn swap_beta_ptlc_alice<T, W>(
        &mut self,
        transport: &mut T,
        wallet: &W,
        ptlc_amount: Amount,
        secret: PtlcSecret,
        _alpha_absolute_expiry: u32,
        tx_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        // TODO: Think about how to handle the three expiries. See
        // https://github.com/comit-network/thor/pull/47#discussion_r480822913.

        let Balance { ours, theirs } = self.balance();

        let theirs = theirs.checked_sub(ptlc_amount).ok_or_else(|| {
            anyhow!(
                "Bob's {} balance cannot cover PTLC output amount: {}",
                theirs,
                ptlc_amount
            )
        })?;

        let out_ours = self.split_balance_output_ours(ours);
        let out_theirs = self.split_balance_output_theirs(theirs);

        let ptlc_output = SplitOutput::Ptlc(Ptlc {
            amount: ptlc_amount,
            X_funder: self.X_other.clone(),
            X_redeemer: self.x_self.public(),
            role: Role::Alice {
                secret: secret.clone(),
            },
            refund_time_lock: ptlc_refund_time_lock,
        });

        self.update(
            transport,
            vec![out_ours, out_theirs, ptlc_output],
            tx_s_time_lock,
        )
        .await?;

        transport
            .send_message(Message::Secret(secret.clone()))
            .await?;

        // Attempt to perform a channel update to merge PTLC output into Alice's balance
        // output

        let out_ours = self.split_balance_output_ours(ours + ptlc_amount);
        let out_theirs = self.split_balance_output_theirs(theirs);

        let channel = self.clone();
        let final_update = self.update(transport, vec![out_ours, out_theirs], tx_s_time_lock);

        // TODO: Configure timeout based on expiries
        let timeout = tokio::time::delay_for(std::time::Duration::from_secs(5));

        pin_mut!(final_update);
        pin_mut!(timeout);

        // If the channel update isn't finished before `timeout`, force close and
        // publish `tx_ptlc_redeem`.
        match futures::future::select(final_update, timeout).await {
            Either::Left((Ok(_), _)) => (),
            Either::Left((Err(_), _)) | Either::Right(_) => {
                // TODO: Have we dropped the other future execution if we reach this block?
                let (_, _, tx_ptlc_redeem, _, encsig_funder, sig_redeemer, ..) = channel
                    .current_state
                    .clone()
                    .into_with_ptlc()
                    .expect("current state must contain PTLC output");

                let sig_funder = signature::decrypt(secret.into(), encsig_funder);

                let tx_ptlc_redeem = tx_ptlc_redeem.add_signatures(
                    (channel.x_self.public(), sig_redeemer),
                    (channel.X_other.clone(), sig_funder),
                )?;

                channel.force_close(wallet).await?;

                wallet.broadcast_signed_transaction(tx_ptlc_redeem).await?;
            }
        };

        Ok(())
    }

    /// Perform an atomic swap with a thor channel as beta ledger in the
    /// role of Bob.
    ///
    /// Calling this function should only take place once the counterparty has
    /// funded the alpha asset.
    #[warn(clippy::too_many_arguments)]
    pub fn swap_beta_ptlc_bob<'a, T>(
        &'a mut self,
        transport: &'a mut T,
        ptlc_amount: Amount,
        point: PtlcPoint,
        _alpha_absolute_expiry: u32,
        tx_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> Gen<PtlcSecret, (), impl Future<Output = Result<()>> + 'a>
    where
        T: SendMessage + ReceiveMessage,
    {
        Gen::new(|co| async move {
            let Balance { ours, theirs } = self.balance();

            let ours = ours.checked_sub(ptlc_amount).ok_or_else(|| {
                anyhow!(
                    "Bob's {} balance cannot cover PTLC output amount: {}",
                    ours,
                    ptlc_amount
                )
            })?;

            let out_ours = self.split_balance_output_ours(ours);
            let out_theirs = self.split_balance_output_theirs(theirs);

            let ptlc_output = SplitOutput::Ptlc(Ptlc {
                amount: ptlc_amount,
                X_funder: self.x_self.public(),
                X_redeemer: self.X_other.clone(),
                role: Role::Bob {
                    point: point.clone(),
                },
                refund_time_lock: ptlc_refund_time_lock,
            });

            self.update(
                transport,
                vec![out_ours, out_theirs, ptlc_output],
                tx_s_time_lock,
            )
            .await?;

            // Wait for Alice to send over the `secret`.

            // TODO: If Alice doesn't reveal the secret and we're approaching
            // `alpha_absolute_expiry` force close the channel. Now monitor the
            // Bitcoin blockchain for Alice revealing the `secret` by publishing
            // `tx_ptlc_redeem`. If she does yield the `secret`. If she doesn't do it before
            // `ptlc_refund_time_lock`, publish `tx_ptlc_refund`.
            let secret = map_err(transport.receive_message().await?.into_secret())?;

            if secret.point() != point {
                bail!("Alice sent incorrect secret")
            }

            co.yield_(secret).await;

            // Perform a channel update to merge PTLC output into Alice's balance output
            let out_ours = self.split_balance_output_ours(ours);
            let out_theirs = self.split_balance_output_theirs(theirs + ptlc_amount);

            self.update(transport, vec![out_ours, out_theirs], tx_s_time_lock)
                .await?;

            Ok(())
        })
    }

    async fn update<T>(
        &mut self,
        transport: &mut T,
        new_split_outputs: Vec<SplitOutput>,
        time_lock: u32,
    ) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        use update::*;

        let state = State0::new(self.clone(), new_split_outputs, time_lock);

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response)?;

        let updated_channel = match state {
            State1Kind::State1(state) => update!(transport, state),
            State1Kind::State1PtlcFunder(state) => {
                transport.send_message(state.compose().into()).await?;
                let response = transport.receive_message().await?.try_into()?;
                let state = state.interpret(response)?;

                update!(transport, state)
            }
            State1Kind::State1PtlcRedeemer(state) => {
                transport.send_message(state.compose().into()).await?;
                let response = transport.receive_message().await?.try_into()?;
                let state = state.interpret(response)?;

                update!(transport, state)
            }
        };

        #[macro_export]
        macro_rules! update {
            ($transport:expr, $state:expr) => {{
                let transport = $transport;
                let state = $state;

                transport.send_message(state.compose().into()).await?;
                let response = transport.receive_message().await?.try_into()?;
                let state = state.interpret(response)?;

                transport.send_message(state.compose().into()).await?;
                let response = transport.receive_message().await?.try_into()?;
                let state = state.interpret(response)?;

                transport.send_message(state.compose().into()).await?;
                let response = transport.receive_message().await?.try_into()?;
                let updated_channel = state.interpret(response)?;

                updated_channel
            }};
        }

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
    pub async fn close<T, W>(&self, transport: &mut T, wallet: &W) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        let state = close::State0::new(&self);

        transport.send_message(state.compose()?.into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let close_transaction = state.interpret(response)?;

        wallet
            .broadcast_signed_transaction(close_transaction)
            .await?;

        Ok(())
    }

    /// Close the channel non-collaboratively.
    pub async fn force_close<W>(&self, wallet: &W) -> Result<()>
    where
        W: NewAddress + BroadcastSignedTransaction,
    {
        let state = StandardChannelState::from(self.current_state.clone());

        let commit = state.signed_tx_c(&self.tx_f_body, &self.x_self, &self.X_other)?;
        wallet.broadcast_signed_transaction(commit).await?;

        let split = state.signed_tx_s;
        wallet.broadcast_signed_transaction(split.into()).await?;

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
            .await?;

        Ok(())
    }

    /// Get the current channel balance.
    pub fn balance(&self) -> Balance {
        let channel_state: &StandardChannelState = self.current_state.as_ref();
        channel_state.balance
    }

    /// Get the transaction id of the initial fund transaction.
    pub fn tx_f_txid(&self) -> Txid {
        self.tx_f_body.txid()
    }

    /// Retrieve the signed `CommitTransaction` of the state that was revoked
    /// during the last channel update.
    pub fn latest_revoked_signed_tx_c(&self) -> Result<Option<Transaction>> {
        self.revoked_states
            .last()
            .map(|state| {
                state.signed_tx_c(&self.tx_f_body, self.x_self.clone(), self.X_other.clone())
            })
            .transpose()
    }

    /// Splice a channel.
    ///
    /// Create a new funding transaction using a previous funding transaction as
    /// input. Also inject own funds to channel by passing a splice-in amount.
    pub async fn splice<T, W>(self, transport: &mut T, wallet: &W, splice: Splice) -> Result<Self>
    where
        W: BroadcastSignedTransaction + BuildFundingPsbt + SignFundingPsbt,
        T: SendMessage + ReceiveMessage,
    {
        // Re-use timelock, final addresses, balance, ownership keys
        let final_address_self = self.final_address_self;
        let final_address_other = self.final_address_other;
        let current_state = StandardChannelState::from(self.current_state);
        let time_lock = current_state.time_lock();
        let balance = current_state.balance;
        let x_self = self.x_self;
        let X_other = self.X_other;

        let state = splice::State0::new(
            time_lock,
            final_address_self,
            final_address_other,
            balance,
            self.tx_f_body,
            x_self,
            X_other,
            splice,
            wallet,
        )
        .await?;

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response)?;

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response)?;

        transport.send_message(state.compose().into()).await?;
        let response = transport.receive_message().await?.try_into()?;
        let state = state.interpret(response, wallet).await?;

        transport
            .send_message(state.compose().await?.into())
            .await?;
        let response = transport.receive_message().await?.try_into()?;
        let (channel, transaction) = state.interpret(response, wallet).await?;

        wallet.broadcast_signed_transaction(transaction).await?;

        Ok(channel)
    }
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
    pub fn signed_tx_c(
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

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub enum SplitOutput {
    Ptlc(Ptlc),
    Balance {
        #[cfg_attr(
            feature = "serde",
            serde(with = "bitcoin::util::amount::serde::as_sat")
        )]
        amount: Amount,
        address: Address,
    },
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Ptlc {
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
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

fn map_err<T>(res: Result<T, Message>) -> Result<T, UnexpectedMessage> {
    res.map_err(UnexpectedMessage::new::<T>)
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
