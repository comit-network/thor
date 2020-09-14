pub mod protocols;

pub use protocols::create::{BuildFundingPsbt, SignFundingPsbt};
use protocols::{close, create, punish::punish, splice, update};

use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey},
    signature, step, step_wallet,
    transaction::{ptlc, FundingTransaction},
    Balance, ChannelState, GetRawTransaction, MedianTime, Message, Ptlc, PtlcPoint, PtlcSecret,
    RevokedState, Role, Splice, SplitOutput, StandardChannelState,
};
use ::serde::{Deserialize, Serialize};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use bitcoin::{Address, Amount, Transaction, Txid};
use futures::{
    future::{Either, FutureExt},
    pin_mut, Future,
};
use genawaiter::sync::Gen;
use std::{convert::TryInto, time::Duration};

#[cfg(test)]
mod tests;

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

        let (transport, state) = step_wallet!(transport, state, wallet);

        let (transport, state) = step!(transport, state);
        let (transport, state) = step!(transport, state);
        let (transport, state) = step!(transport, state);
        let (transport, state) = step!(transport, state);

        // No step macro because compose() requires the wallet.
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
        alpha_absolute_expiry: u32,
        tx_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
        W: NewAddress + BroadcastSignedTransaction,
    {
        let tx_ptlc_redeem = self
            .add_ptlc_redeemer(
                transport,
                ptlc_amount,
                secret.clone(),
                tx_s_time_lock,
                ptlc_refund_time_lock,
            )
            .await?;

        self.redeem_ptlc_redeemer(
            transport,
            wallet,
            ptlc_amount,
            secret,
            alpha_absolute_expiry,
            tx_s_time_lock,
            ptlc_refund_time_lock,
            tx_ptlc_redeem,
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
        tx_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> Result<ptlc::RedeemTransaction>
    where
        T: SendMessage + ReceiveMessage,
    {
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

        let tx_ptlc_redeem = {
            let (_, _, tx_ptlc_redeem, _, encsig_funder, sig_redeemer, ..) = self
                .current_state
                .clone()
                .into_with_ptlc()
                .expect("current state contains PTLC output");

            let sig_funder = signature::decrypt(secret.clone().into(), encsig_funder);

            tx_ptlc_redeem.add_signatures(
                (self.x_self.public(), sig_redeemer),
                (self.X_other.clone(), sig_funder),
            )?
        };

        Ok(tx_ptlc_redeem)
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
        tx_s_time_lock: u32,
        _ptlc_refund_time_lock: u32,
        tx_ptlc_redeem: ptlc::RedeemTransaction,
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

        let out_ours = self.split_balance_output_ours(ours + ptlc_amount);
        let out_theirs = self.split_balance_output_theirs(theirs);

        let channel = self.clone();
        let final_update = self.update(transport, vec![out_ours, out_theirs], tx_s_time_lock);

        // TODO: Configure timeout based on expiries
        let timeout = tokio::time::delay_for(std::time::Duration::from_secs(10));

        pin_mut!(final_update);
        pin_mut!(timeout);

        // If the channel update isn't finished before `timeout`, force close and
        // publish `tx_ptlc_redeem`.
        match futures::future::select(final_update, timeout).await {
            Either::Left((Ok(_), _)) => (),
            Either::Left((Err(_), _)) | Either::Right(_) => {
                channel.force_close(wallet).await?;

                wallet
                    .broadcast_signed_transaction(tx_ptlc_redeem.into())
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
        tx_s_time_lock: u32,
        ptlc_refund_time_lock: u32,
    ) -> Gen<PtlcSecret, (), impl Future<Output = Result<()>> + 'a>
    where
        T: SendMessage + ReceiveMessage,
        W: MedianTime + NewAddress + BroadcastSignedTransaction + GetRawTransaction,
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

            let ptlc_almost_expired = async {
                // `TX_s_time_lock` is a relative timelock in blocks. To convert it to an
                // estimated relative timelock in seconds we use 10 minutes as the average
                // blocktime for Bitcoin.
                let tx_s_time_lock_in_seconds = tx_s_time_lock * 10 * 60;
                let ptlc_nearing_expiry_time = ptlc_refund_time_lock - tx_s_time_lock_in_seconds;

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
                    let secret: PtlcSecret = message.try_into()?;
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
                        tx_s_time_lock,
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
    ) -> Result<()>
    where
        T: SendMessage + ReceiveMessage,
    {
        use update::*;
        use State1Kind::*;

        macro_rules! update {
            ($transport:expr, $state:expr) => {{
                let transport = $transport;
                let state = $state;

                let (transport, state) = step!(transport, state);
                let (transport, state) = step!(transport, state);
                let (_, updated_channel) = step!(transport, state);

                updated_channel
            }};
        }

        let state = State0::new(self.clone(), new_split_outputs, time_lock);

        let (transport, state) = step!(transport, state);

        let updated_channel = match state {
            State1(state) => update!(transport, state),
            State1PtlcFunder(state) => {
                let (transport, state) = step!(transport, state);
                update!(transport, state)
            }
            State1PtlcRedeemer(state) => {
                let (transport, state) = step!(transport, state);
                update!(transport, state)
            }
        };

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
        let state = close::State0::new(&self)?;

        let (_, close_transaction) = step!(transport, state);
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
    #[cfg(test)]
    fn latest_revoked_signed_tx_c(&self) -> Result<Option<Transaction>> {
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

        let (transport, state) = step!(transport, state);
        let (transport, state) = step!(transport, state);
        let (transport, state) = step_wallet!(transport, state, wallet);
        let (_, (channel, transaction)) = step_wallet!(transport, state, wallet);

        wallet.broadcast_signed_transaction(transaction).await?;

        Ok(channel)
    }
}
