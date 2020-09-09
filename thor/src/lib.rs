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

#[cfg(test)]
mod edge_case_tests;
#[cfg(test)]
mod public_api_tests;
#[cfg(test)]
mod test_harness;

pub use ::bitcoin;
pub use keys::{PtlcPoint, PtlcSecret};
pub use protocols::create::{BuildFundingPSBT, SignFundingPSBT};

use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    protocols::punish::punish,
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
};
use anyhow::bail;
use bitcoin::{Address, Amount, Transaction, Txid};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use enum_as_inner::EnumAsInner;
use futures::{
    future::{Either, FutureExt},
    pin_mut, Future,
};
use genawaiter::sync::Gen;
use protocols::{close, create, splice, update};
use signature::decrypt;
use std::time::Duration;
use transaction::ptlc;

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

#[async_trait::async_trait]
pub trait MedianTime {
    async fn median_time(&self) -> anyhow::Result<u32>;
}

#[async_trait::async_trait]
pub trait GetRawTransaction {
    async fn get_raw_transaction(&self, txid: Txid) -> anyhow::Result<Transaction>;
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
        T: SendMessage + ReceiveMessage,
        W: BuildFundingPSBT + SignFundingPSBT + BroadcastSignedTransaction + NewAddress,
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
    pub async fn update_balance<T>(
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

        self.update(
            transport,
            vec![split_output_self, split_output_other],
            time_lock,
        )
        .await
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
        alpha_absolute_expiry: u32,
        TX_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        let TX_ptlc_redeem = self
            .add_ptlc_redeemer(
                transport,
                ptlc_amount,
                secret.clone(),
                TX_s_time_lock,
                ptlc_refund_time_lock,
            )
            .await?;

        self.redeem_ptlc_redeemer(
            transport,
            wallet,
            ptlc_amount,
            secret,
            alpha_absolute_expiry,
            TX_s_time_lock,
            ptlc_refund_time_lock,
            TX_ptlc_redeem,
        )
        .await?;

        Ok(())
    }

    /// Update the channel to add a PTLC output whose funds will come from the
    /// balance output of the counterparty and, if successfully redeemed,
    /// will pay to us.
    async fn add_ptlc_redeemer<T>(
        &mut self,
        transport: &mut T,
        ptlc_amount: Amount,
        secret: PtlcSecret,
        TX_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> anyhow::Result<ptlc::RedeemTransaction>
    where
        T: SendMessage + ReceiveMessage,
    {
        let Balance { ours, theirs } = self.balance();

        let theirs = theirs.checked_sub(ptlc_amount).ok_or_else(|| {
            anyhow::anyhow!(
                "Bob's {} balance cannot cover PTLC output amount: {}",
                theirs,
                ptlc_amount
            )
        })?;

        let balance_output_self = SplitOutput::Balance {
            amount: ours,
            address: self.final_address_self.clone(),
        };

        let balance_output_other = SplitOutput::Balance {
            amount: theirs,
            address: self.final_address_other.clone(),
        };

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
            vec![balance_output_self, balance_output_other, ptlc_output],
            TX_s_time_lock,
        )
        .await?;

        let TX_ptlc_redeem = {
            let (_, _, TX_ptlc_redeem, _, encsig_funder, sig_redeemer, ..) = self
                .current_state
                .clone()
                .into_with_ptlc()
                .expect("current state contains PTLC output");

            let sig_funder = signature::decrypt(secret.clone().into(), encsig_funder);

            TX_ptlc_redeem.add_signatures(
                (self.x_self.public(), sig_redeemer),
                (self.X_other.clone(), sig_funder),
            )?
        };

        Ok(TX_ptlc_redeem)
    }

    /// Attempt to redeem a PTLC output.
    ///
    /// If it's still safe (PTLC is not close to expiry), send the secret to the
    /// counterparty and attempt to perform a channel update to merge the PTLC
    /// output into our balance output. If the counterparty does not cooperate
    /// soon enough after the revelation of the secret, force close the channel
    /// and publish the redeem transaction.
    #[allow(clippy::too_many_arguments)]
    async fn redeem_ptlc_redeemer<T, W>(
        &mut self,
        transport: &mut T,
        wallet: &W,
        ptlc_amount: Amount,
        secret: PtlcSecret,
        _alpha_absolute_expiry: u32,
        TX_s_time_lock: u32,
        _ptlc_refund_time_lock: u32,
        TX_ptlc_redeem: ptlc::RedeemTransaction,
    ) -> anyhow::Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        // TODO: Check that `ptlc_refund_time_lock` is not close, otherwise abort
        transport.send_message(Message::Secret(secret)).await?;

        // Attempt to perform a channel update to merge PTLC output into Alice's balance
        // output
        let Balance { ours, theirs } = self.balance();

        let balance_output_self = SplitOutput::Balance {
            amount: ours + ptlc_amount,
            address: self.final_address_self.clone(),
        };

        let balance_output_other = SplitOutput::Balance {
            amount: theirs,
            address: self.final_address_other.clone(),
        };

        let channel = self.clone();
        let final_update = self.update(
            transport,
            vec![balance_output_self, balance_output_other],
            TX_s_time_lock,
        );

        // TODO: Configure timeout based on expiries
        let timeout = tokio::time::delay_for(std::time::Duration::from_secs(10));

        pin_mut!(final_update);
        pin_mut!(timeout);

        // If the channel update isn't finished before `timeout`, force close and
        // publish `TX_ptlc_redeem`.
        match futures::future::select(final_update, timeout).await {
            Either::Left((Ok(_), _)) => (),
            Either::Left((Err(_), _)) | Either::Right(_) => {
                channel.force_close(wallet).await?;

                wallet
                    .broadcast_signed_transaction(TX_ptlc_redeem.into())
                    .await?;
            }
        };

        Ok(())
    }

    /// Perform an atomic swap with a thor channel as beta ledger in the
    /// role of Bob.
    ///
    /// Calling this function should only take place once the counterparty has
    /// funded the alpha asset.
    #[allow(clippy::too_many_arguments)]
    pub fn swap_beta_ptlc_bob<'a, T, W>(
        &'a mut self,
        transport: &'a mut T,
        wallet: &'a W,
        ptlc_amount: Amount,
        point: PtlcPoint,
        _alpha_absolute_expiry: u32,
        TX_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> Gen<PtlcSecret, (), impl Future<Output = anyhow::Result<()>> + 'a>
    where
        T: SendMessage + ReceiveMessage,
        W: MedianTime + NewAddress + BroadcastSignedTransaction + GetRawTransaction,
    {
        Gen::new(|co| async move {
            let Balance { ours, theirs } = self.balance();

            let ours = ours.checked_sub(ptlc_amount).ok_or_else(|| {
                anyhow::anyhow!(
                    "Bob's {} balance cannot cover PTLC output amount: {}",
                    ours,
                    ptlc_amount
                )
            })?;

            let balance_output_self = SplitOutput::Balance {
                amount: ours,
                address: self.final_address_self.clone(),
            };

            let balance_output_other = SplitOutput::Balance {
                amount: theirs,
                address: self.final_address_other.clone(),
            };

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
                vec![balance_output_self, balance_output_other, ptlc_output],
                TX_s_time_lock,
            )
            .await?;

            // Wait for Alice to send over the `secret`.

            let ptlc_almost_expired = async {
                // `TX_s_time_lock` is a relative timelock in blocks. To convert it to an
                // estimated relative timelock in seconds we use 10 minutes as the average
                // blocktime for Bitcoin.
                let TX_s_time_lock_in_seconds = TX_s_time_lock * 10 * 60;
                let ptlc_nearing_expiry_time = ptlc_refund_time_lock - TX_s_time_lock_in_seconds;

                loop {
                    let median_time = wallet.median_time().await?;

                    if median_time >= ptlc_nearing_expiry_time {
                        return Result::<(), anyhow::Error>::Ok(());
                    }

                    tokio::time::delay_for(Duration::from_secs(1)).await;
                }
            };

            // The mutex is only needed because the compiler cannot verify that the mutable
            // borrow on transport ends if the `ptlc_almost_expired` future is the one that
            // resolves first in the select
            let transport = futures::lock::Mutex::new(transport);

            let secret_revealed = async {
                let mut transport = transport.lock().await;
                transport.receive_message().await
            };

            pin_mut!(ptlc_almost_expired);
            pin_mut!(secret_revealed);

            match futures::future::select(secret_revealed, ptlc_almost_expired).await {
                Either::Left((Ok(message), _)) => {
                    // TODO: If the message cannot be converted into a valid secret we should run
                    // the other branch
                    let secret = map_err(message.into_secret())?;

                    if secret.point() != point {
                        bail!("Alice sent incorrect secret")
                    }

                    co.yield_(secret).await;

                    // Perform a channel update to merge PTLC output into Alice's balance output

                    let balance_output_self = SplitOutput::Balance {
                        amount: ours,
                        address: self.final_address_self.clone(),
                    };

                    let balance_output_other = SplitOutput::Balance {
                        amount: theirs + ptlc_amount,
                        address: self.final_address_other.clone(),
                    };

                    let mut transport = transport.lock().await;
                    self.update(
                        *transport,
                        vec![balance_output_self, balance_output_other],
                        TX_s_time_lock,
                    )
                    .await?;
                }
                Either::Left((Err(_), _)) | Either::Right(_) => {
                    self.force_close(wallet).await?;

                    let (_, _, TX_ptlc_redeem, TX_ptlc_refund, encsig_TX_ptlc_redeem_funder, ..) =
                        self.current_state
                            .clone()
                            .into_with_ptlc()
                            .expect("current state contains PTLC output");

                    let ptlc_expired = async {
                        loop {
                            if wallet.median_time().await? >= ptlc_refund_time_lock {
                                return Result::<(), anyhow::Error>::Ok(());
                            }

                            tokio::time::delay_for(Duration::from_secs(1)).await;
                        }
                    };
                    let watch_redeem = async {
                        loop {
                            if let Ok(transaction) =
                                wallet.get_raw_transaction(TX_ptlc_redeem.txid()).await
                            {
                                return transaction;
                            };

                            tokio::time::delay_for(Duration::from_secs(1)).await;
                        }
                    };

                    futures::select! {
                        _ = ptlc_expired.fuse() => {
                            wallet
                                .broadcast_signed_transaction(TX_ptlc_refund.into())
                                .await?;
                        },
                        candidate_transaction = watch_redeem.fuse() => {
                            let sig_TX_ptlc_redeem_funder = ptlc::extract_signature_by_key(
                                candidate_transaction,
                                TX_ptlc_redeem,
                                self.x_self.public(),
                            )?;

                            let secret = ptlc::recover_secret(
                                point,
                                sig_TX_ptlc_redeem_funder,
                                encsig_TX_ptlc_redeem_funder,
                            )?;

                            co.yield_(secret).await;
                        },
                    };
                }
            }

            Ok(())
        })
    }

    async fn update<T>(
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

        let updated_channel = match state1 {
            update::State1Kind::State1(state1) => update!(transport, state1),
            update::State1Kind::State1PtlcFunder(state1_ptlc_funder) => {
                let msg_self = state1_ptlc_funder.compose();
                transport
                    .send_message(Message::UpdatePtlcFunder(msg_self))
                    .await?;

                let msg_other = map_err(
                    transport
                        .receive_message()
                        .await?
                        .into_update_ptlc_redeemer(),
                )?;
                let state1 = state1_ptlc_funder.interpret(msg_other)?;

                update!(transport, state1)
            }
            update::State1Kind::State1PtlcRedeemer(state1_ptlc_redeemer) => {
                let msg_self = state1_ptlc_redeemer.compose();
                transport
                    .send_message(Message::UpdatePtlcRedeemer(msg_self))
                    .await?;

                let msg_other =
                    map_err(transport.receive_message().await?.into_update_ptlc_funder())?;
                let state1 = state1_ptlc_redeemer.interpret(msg_other)?;

                update!(transport, state1)
            }
        };

        #[macro_export]
        macro_rules! update {
            ($transport:expr, $state1:expr) => {{
                let transport = $transport;
                let state1 = $state1;

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
    pub async fn close<T, W>(&self, transport: &mut T, wallet: &W) -> anyhow::Result<()>
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

    pub async fn force_close<W>(&self, wallet: &W) -> anyhow::Result<()>
    where
        W: NewAddress + BroadcastSignedTransaction,
    {
        let current_state = StandardChannelState::from(self.current_state.clone());

        let commit_transaction =
            current_state.signed_TX_c(&self.TX_f_body, &self.x_self, &self.X_other)?;
        wallet
            .broadcast_signed_transaction(commit_transaction)
            .await?;

        let split_transaction = current_state.signed_TX_s.clone();
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
        let channel_state: &StandardChannelState = self.current_state.as_ref();
        channel_state.balance
    }

    pub fn TX_f_txid(&self) -> Txid {
        self.TX_f_body.txid()
    }

    /// Retrieve the signed `CommitTransaction` of the state that was revoked
    /// during the last channel update.
    pub fn latest_revoked_signed_TX_c(&self) -> anyhow::Result<Option<Transaction>> {
        self.revoked_states
            .last()
            .map(|state| {
                state.signed_TX_c(&self.TX_f_body, self.x_self.clone(), self.X_other.clone())
            })
            .transpose()
    }

    /// Splice a channel.
    ///
    /// Create a new funding transaction using a previous funding transaction as
    /// input. Also inject own funds to channel by passing a splice-in amount.
    pub async fn splice<T, W>(
        self,
        transport: &mut T,
        wallet: &W,
        splice_in: Option<Amount>,
    ) -> anyhow::Result<Self>
    where
        W: BroadcastSignedTransaction + BuildFundingPSBT + SignFundingPSBT,
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

        let state0 = splice::State0::new(
            time_lock,
            final_address_self,
            final_address_other,
            balance,
            self.TX_f_body,
            x_self,
            X_other,
            splice_in,
            wallet,
        )
        .await?;

        let msg0_self = state0.next_message();
        transport.send_message(Message::Splice0(msg0_self)).await?;

        let msg0_other = map_err(transport.receive_message().await?.into_splice0())?;
        let state1 = state0.receive(msg0_other)?;

        let msg1_self = state1.next_message();
        transport.send_message(Message::Splice1(msg1_self)).await?;

        let msg1_other = map_err(transport.receive_message().await?.into_splice1())?;
        let state2 = state1.receive(msg1_other)?;

        let msg2_self = state2.next_message();
        transport.send_message(Message::Splice2(msg2_self)).await?;

        let msg2_other = map_err(transport.receive_message().await?.into_splice2())?;
        let state3 = state2.receive(msg2_other, wallet).await?;

        let msg3_self = state3.next_message().await?;
        transport.send_message(Message::Splice3(msg3_self)).await?;

        let msg3_other = map_err(transport.receive_message().await?.into_splice3())?;

        let (channel, transaction) = state3.receive(msg3_other, wallet).await?;

        wallet.broadcast_signed_transaction(transaction).await?;

        Ok(channel)
    }
}

#[allow(clippy::large_enum_variant)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug, EnumAsInner)]
pub(crate) enum ChannelState {
    Standard(StandardChannelState),
    WithPtlc {
        inner: StandardChannelState,
        ptlc: Ptlc,
        TX_ptlc_redeem: ptlc::RedeemTransaction,
        TX_ptlc_refund: ptlc::RefundTransaction,
        encsig_TX_ptlc_redeem_funder: EncryptedSignature,
        sig_TX_ptlc_redeem_redeemer: Signature,
        sig_TX_ptlc_refund_funder: Signature,
        sig_TX_ptlc_refund_redeemer: Signature,
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

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct StandardChannelState {
    /// Proportion of the coins in the channel that currently belong to either
    /// party. To actually claim these coins one or more transactions will have
    /// to be submitted to the blockchain, so in practice the balance will see a
    /// reduction to pay for transaction fees.
    balance: Balance,
    TX_c: CommitTransaction,
    /// Encrypted signature received from the counterparty. It can be decrypted
    /// using our `PublishingSecretkey` and used to sign `TX_c`. Keep in mind,
    /// that publishing a revoked `TX_c` will allow the counterparty to punish
    /// us.
    encsig_TX_c_other: EncryptedSignature,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    /// Signed `SplitTransaction`.
    signed_TX_s: SplitTransaction,
}

impl StandardChannelState {
    fn signed_TX_c(
        &self,
        TX_f: &FundingTransaction,
        x_self: &OwnershipKeyPair,
        X_other: &OwnershipPublicKey,
    ) -> anyhow::Result<Transaction> {
        let sig_self = self.TX_c.sign_once(x_self);
        let sig_other = decrypt(self.y_self.clone().into(), self.encsig_TX_c_other.clone());

        let signed_TX_c = self.TX_c.clone().add_signatures(
            TX_f,
            (x_self.public(), sig_self),
            (X_other.clone(), sig_other),
        )?;

        Ok(signed_TX_c)
    }

    pub fn time_lock(&self) -> u32 {
        self.TX_c.time_lock()
    }

    pub fn encsign_TX_c_self(&self, x_self: &OwnershipKeyPair) -> EncryptedSignature {
        self.TX_c.encsign_once(x_self, self.Y_other.clone())
    }
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
pub(crate) struct RevokedState {
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
        TX_f: &FundingTransaction,
        x_self: keys::OwnershipKeyPair,
        X_other: OwnershipPublicKey,
    ) -> anyhow::Result<Transaction> {
        StandardChannelState::from(self.channel_state.clone()).signed_TX_c(TX_f, &x_self, &X_other)
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

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
