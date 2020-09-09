use crate::{
    channel::ChannelState,
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    transaction::{balance, CommitTransaction, FundOutput, FundingTransaction, SplitTransaction},
    Balance, Channel, SplitOutput, StandardChannelState,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount, Transaction};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    X: OwnershipPublicKey,
    final_address: Address,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message1 {
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction")
    )]
    input_psbt: PartiallySignedTransaction,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message2 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message3 {
    sig_tx_s: Signature,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message4 {
    encsig_tx_c: EncryptedSignature,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message5 {
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction")
    )]
    tx_f_signed_once: PartiallySignedTransaction,
}

#[derive(Debug)]
pub(in crate::channel) struct State0 {
    x_self: OwnershipKeyPair,
    final_address_self: Address,
    balance: Balance,
    time_lock: u32,
}

#[async_trait]
pub trait BuildFundingPSBT {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> Result<PartiallySignedTransaction>;
}

impl State0 {
    pub(in crate::channel) fn new(
        balance: Balance,
        time_lock: u32,
        final_address: Address,
    ) -> Self {
        let x_self = OwnershipKeyPair::new_random();

        Self {
            x_self,
            balance,
            final_address_self: final_address,
            time_lock,
        }
    }

    pub(in crate::channel) fn compose(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            final_address: self.final_address_self.clone(),
        }
    }

    pub(in crate::channel) async fn interpret(
        self,
        Message0 {
            X: X_other,
            final_address: final_address_other,
        }: Message0,
        wallet: &impl BuildFundingPSBT,
    ) -> Result<State1> {
        let fund_output = FundOutput::new([self.x_self.public(), X_other.clone()]);
        let input_psbt_self = wallet
            .build_funding_psbt(fund_output.address(), self.balance.ours)
            .await?;

        Ok(State1 {
            x_self: self.x_self,
            X_other,
            final_address_self: self.final_address_self,
            final_address_other,
            balance: self.balance,
            input_psbt_self,
            time_lock: self.time_lock,
        })
    }
}

#[derive(Debug)]
pub(in crate::channel) struct State1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    input_psbt_self: PartiallySignedTransaction,
    time_lock: u32,
}

impl State1 {
    pub(in crate::channel) fn compose(&self) -> Message1 {
        Message1 {
            input_psbt: self.input_psbt_self.clone(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        Message1 {
            input_psbt: input_pstb_other,
        }: Message1,
    ) -> Result<State2> {
        let tx_f = FundingTransaction::new(vec![self.input_psbt_self.clone(), input_pstb_other], [
            (self.x_self.public(), self.balance.ours),
            (self.X_other.clone(), self.balance.theirs),
        ])
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(State2 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance: self.balance,
            time_lock: self.time_lock,
            r_self: r,
            y_self: y,
            tx_f,
        })
    }
}

#[derive(Clone, Debug)]
pub(in crate::channel) struct State2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    tx_f: FundingTransaction,
}

impl State2 {
    pub(in crate::channel) fn compose(&self) -> Message2 {
        Message2 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        Message2 {
            R: R_other,
            Y: Y_other,
        }: Message2,
    ) -> Result<State3> {
        let tx_c = CommitTransaction::new(
            &self.tx_f,
            [
                (
                    self.x_self.public(),
                    self.r_self.public(),
                    self.y_self.public(),
                ),
                (self.X_other.clone(), R_other.clone(), Y_other.clone()),
            ],
            self.time_lock,
        )?;

        let split_outputs = vec![
            SplitOutput::Balance {
                amount: self.balance.ours,
                address: self.final_address_self.clone(),
            },
            SplitOutput::Balance {
                amount: self.balance.theirs,
                address: self.final_address_other.clone(),
            },
        ];
        let tx_s = SplitTransaction::new(&tx_c, split_outputs.clone())?;
        let sig_tx_s_self = tx_s.sign_once(&self.x_self);

        Ok(State3 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            split_outputs,
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            tx_f: self.tx_f,
            tx_c,
            tx_s,
            sig_tx_s_self,
        })
    }
}

#[derive(Debug)]
pub(in crate::channel) struct State3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    split_outputs: Vec<SplitOutput>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    tx_f: FundingTransaction,
    tx_c: CommitTransaction,
    tx_s: SplitTransaction,
    sig_tx_s_self: Signature,
}

impl State3 {
    pub(in crate::channel) fn compose(&self) -> Message3 {
        Message3 {
            sig_tx_s: self.sig_tx_s_self.clone(),
        }
    }

    pub(in crate::channel) fn interpret(
        mut self,
        Message3 {
            sig_tx_s: sig_tx_s_other,
        }: Message3,
    ) -> Result<State4> {
        self.tx_s
            .verify_sig(self.X_other.clone(), &sig_tx_s_other)
            .context("failed to verify sig_tx_s sent by counterparty")?;

        self.tx_s.add_signatures(
            (self.x_self.public(), self.sig_tx_s_self),
            (self.X_other.clone(), sig_tx_s_other),
        )?;

        let encsig_tx_c_self = self.tx_c.encsign_once(&self.x_self, self.Y_other.clone());

        Ok(State4 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            split_outputs: self.split_outputs,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            tx_f: self.tx_f,
            tx_c: self.tx_c,
            signed_tx_s: self.tx_s,
            encsig_tx_c_self,
        })
    }
}

#[derive(Debug)]
pub(in crate::channel) struct State4 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    split_outputs: Vec<SplitOutput>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    tx_f: FundingTransaction,
    tx_c: CommitTransaction,
    signed_tx_s: SplitTransaction,
    encsig_tx_c_self: EncryptedSignature,
}

impl State4 {
    pub(in crate::channel) fn compose(&self) -> Message4 {
        Message4 {
            encsig_tx_c: self.encsig_tx_c_self.clone(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        Message4 {
            encsig_tx_c: encsig_tx_c_other,
        }: Message4,
    ) -> Result<State5> {
        self.tx_c
            .verify_encsig(
                self.X_other.clone(),
                self.y_self.public(),
                &encsig_tx_c_other,
            )
            .context("failed to verify encsig_tx_c sent by counterparty")?;

        Ok(State5 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            split_outputs: self.split_outputs,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            tx_f: self.tx_f,
            tx_c: self.tx_c,
            signed_tx_s: self.signed_tx_s,
            encsig_tx_c_other,
        })
    }
}

#[derive(Debug)]
pub(in crate::channel) struct State5 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    split_outputs: Vec<SplitOutput>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    tx_f: FundingTransaction,
    tx_c: CommitTransaction,
    signed_tx_s: SplitTransaction,
    encsig_tx_c_other: EncryptedSignature,
}

/// Sign one of the inputs of the `FundingTransaction`.
#[async_trait]
pub trait SignFundingPSBT {
    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction>;
}

impl State5 {
    pub(in crate::channel) async fn compose(
        &self,
        wallet: &impl SignFundingPSBT,
    ) -> Result<Message5> {
        let tx_f_signed_once = wallet
            .sign_funding_psbt(self.tx_f.clone().into_psbt()?)
            .await?;

        Ok(Message5 { tx_f_signed_once })
    }

    /// Returns the Channel and the transaction to broadcast.
    pub(in crate::channel) async fn interpret(
        self,
        Message5 { tx_f_signed_once }: Message5,
        wallet: &impl SignFundingPSBT,
    ) -> Result<(Channel, Transaction)> {
        let signed_tx_f = wallet.sign_funding_psbt(tx_f_signed_once).await?;
        let signed_tx_f = signed_tx_f.extract_tx();

        Ok((
            Channel {
                x_self: self.x_self,
                X_other: self.X_other,
                final_address_self: self.final_address_self.clone(),
                final_address_other: self.final_address_other.clone(),
                tx_f_body: self.tx_f,
                current_state: ChannelState::Standard(StandardChannelState {
                    balance: balance(
                        self.split_outputs,
                        &self.final_address_self,
                        &self.final_address_other,
                    ),
                    tx_c: self.tx_c,
                    encsig_tx_c_other: self.encsig_tx_c_other,
                    r_self: self.r_self,
                    R_other: self.R_other,
                    y_self: self.y_self,
                    Y_other: self.Y_other,
                    signed_tx_s: self.signed_tx_s,
                }),
                revoked_states: vec![],
            },
            signed_tx_f,
        ))
    }
}
