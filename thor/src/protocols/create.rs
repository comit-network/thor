use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    signature::{verify_encsig, verify_sig},
    transaction::{CommitTransaction, FundOutput, SplitTransaction},
    Balance, Channel, ChannelState,
};
use anyhow::Context;
use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount, Transaction};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};

pub use crate::transaction::FundingTransaction;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    X: OwnershipPublicKey,
    final_address: Address,
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
    fund_amount: Amount,
    time_lock: u32,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message1 {
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction")
    )]
    tid: PartiallySignedTransaction,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message2 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message3 {
    sig_TX_s: Signature,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message4 {
    encsig_TX_c: EncryptedSignature,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message5 {
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction")
    )]
    TX_f_signed_once: PartiallySignedTransaction,
}

#[derive(Debug)]
pub struct State0 {
    x_self: OwnershipKeyPair,
    final_address_self: Address,
    fund_amount_self: Amount,
    time_lock: u32,
}

#[async_trait::async_trait]
pub trait BuildFundingPSBT {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> anyhow::Result<PartiallySignedTransaction>;
}

impl State0 {
    pub fn new(fund_amount: Amount, time_lock: u32, final_address: Address) -> Self {
        let x_self = OwnershipKeyPair::new_random();

        Self {
            x_self,
            fund_amount_self: fund_amount,
            final_address_self: final_address,
            time_lock,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            final_address: self.final_address_self.clone(),
            fund_amount: self.fund_amount_self,
            time_lock: self.time_lock,
        }
    }

    pub async fn receive(
        self,
        Message0 {
            X: X_other,
            final_address: final_address_other,
            fund_amount: fund_amount_other,
            time_lock: time_lock_other,
        }: Message0,
        wallet: &impl BuildFundingPSBT,
    ) -> anyhow::Result<State1> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory, together with
        // the time_lock
        check_timelocks(self.time_lock, time_lock_other)?;

        let fund_output = FundOutput::new([self.x_self.public(), X_other.clone()]);
        dbg!(&fund_output);
        let tid_self = wallet
            .build_funding_psbt(fund_output.address(), self.fund_amount_self)
            .await?;

        let balance = Balance {
            ours: self.fund_amount_self,
            theirs: fund_amount_other,
        };

        Ok(State1 {
            x_self: self.x_self,
            X_other,
            final_address_self: self.final_address_self,
            final_address_other,
            balance,
            tid_self,
            time_lock: self.time_lock,
        })
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("time_locks are not equal")]
pub struct IncompatibleTimeLocks;

fn check_timelocks(time_lock_self: u32, time_lock_other: u32) -> Result<(), IncompatibleTimeLocks> {
    if time_lock_self != time_lock_other {
        Err(IncompatibleTimeLocks)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub struct State1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    tid_self: PartiallySignedTransaction,
    time_lock: u32,
}

impl State1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            tid: self.tid_self.clone(),
        }
    }

    pub fn receive(self, Message1 { tid: tid_other }: Message1) -> anyhow::Result<State2> {
        let TX_f = FundingTransaction::new(
            (
                self.x_self.public(),
                self.tid_self.clone(),
                self.balance.ours,
            ),
            (self.X_other.clone(), tid_other, self.balance.theirs),
        )
        .context("failed to build funding transaction")?;

        dbg!(&TX_f);

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
            TX_f,
        })
    }
}

#[derive(Clone, Debug)]
pub struct State2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl State2 {
    pub fn next_message(&self) -> Message2 {
        Message2 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        self,
        Message2 {
            R: R_other,
            Y: Y_other,
        }: Message2,
    ) -> anyhow::Result<Party3> {
        let TX_c = CommitTransaction::new(
            &self.TX_f,
            &[
                (
                    self.x_self.public(),
                    self.r_self.public(),
                    self.y_self.public(),
                ),
                (self.X_other.clone(), R_other.clone(), Y_other.clone()),
            ],
            self.time_lock,
        )?;
        let encsig_TX_c_self = dbg!(&TX_c).encsign_once(self.x_self.clone(), Y_other.clone());

        let half_amount = TX_c.value() / 2;
        let TX_s = SplitTransaction::new(
            &TX_c,
            half_amount,
            self.final_address_self.clone(),
            half_amount,
            self.final_address_other.clone(),
        );
        let sig_TX_s_self = dbg!(&TX_s).sign_once(self.x_self.clone());

        Ok(Party3 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance: self.balance,
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            TX_f: self.TX_f,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        })
    }
}

#[derive(Debug)]
pub struct Party3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
}

impl Party3 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub fn receive(
        mut self,
        Message3 {
            sig_TX_s: sig_TX_s_other,
        }: Message3,
    ) -> anyhow::Result<Party4> {
        verify_sig(self.X_other.clone(), &self.TX_s.digest(), &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        self.TX_s.add_signatures(
            (self.x_self.public(), self.sig_TX_s_self),
            (self.X_other.clone(), sig_TX_s_other),
        )?;

        Ok(Party4 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance: self.balance,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            signed_TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
        })
    }
}

#[derive(Debug)]
pub struct Party4 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
}

impl Party4 {
    pub fn next_message(&self) -> Message4 {
        Message4 {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message4 {
            encsig_TX_c: encsig_TX_c_other,
        }: Message4,
    ) -> anyhow::Result<Party5> {
        verify_encsig(
            self.X_other.clone(),
            self.y_self.public(),
            &self.TX_c,
            &encsig_TX_c_other,
        )
        .context("failed to verify encsig_TX_c sent by counterparty")?;

        Ok(Party5 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance: self.balance,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            signed_TX_s: self.signed_TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other,
        })
    }
}

#[derive(Debug)]
pub struct Party5 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
}

/// Sign one of the inputs of the `FundingTransaction`.
#[async_trait::async_trait]
pub trait SignFundingPSBT {
    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> anyhow::Result<PartiallySignedTransaction>;
}

impl Party5 {
    pub async fn next_message(&self, wallet: &impl SignFundingPSBT) -> anyhow::Result<Message5> {
        let TX_f_signed_once = wallet
            .sign_funding_psbt(self.TX_f.clone().into_psbt()?)
            .await?;

        Ok(Message5 { TX_f_signed_once })
    }

    /// Returns the Channel and the transaction to broadcast.
    pub async fn receive(
        self,
        Message5 { TX_f_signed_once }: Message5,
        wallet: &impl SignFundingPSBT,
    ) -> anyhow::Result<(Channel, Transaction)> {
        let signed_TX_f = wallet.sign_funding_psbt(TX_f_signed_once).await?;
        let signed_TX_f = signed_TX_f.extract_tx();

        Ok((
            Channel {
                x_self: self.x_self,
                X_other: self.X_other,
                final_address_self: self.final_address_self,
                final_address_other: self.final_address_other,
                TX_f_body: self.TX_f,
                current_state: ChannelState {
                    balance: self.balance,
                    TX_c: self.TX_c,
                    encsig_TX_c_self: self.encsig_TX_c_self,
                    encsig_TX_c_other: self.encsig_TX_c_other,
                    r_self: self.r_self,
                    R_other: self.R_other,
                    y_self: self.y_self,
                    Y_other: self.Y_other,
                    signed_TX_s: self.signed_TX_s,
                },
                revoked_states: vec![],
            },
            signed_TX_f,
        ))
    }
}
