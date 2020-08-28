use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    transaction::{CommitTransaction, SplitTransaction},
    Balance, Channel, ChannelState,
};
use anyhow::Context;
use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount, Transaction};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};

pub use crate::transaction::FundingTransaction;
use miniscript::Descriptor;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message1 {
    sig_TX_s: Signature,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message2 {
    encsig_TX_c: EncryptedSignature,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message3 {
    sig_TX_f: Signature,
}

#[derive(Clone, Debug)]
pub(crate) struct State0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    previous_balance: Balance,
    previous_TX_f: FundingTransaction,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
}

impl State0 {
    pub fn new(
        time_lock: u32,
        final_address_self: Address,
        final_address_other: Address,
        previous_balance: Balance,
        previous_TX_f: FundingTransaction,
        x_self: OwnershipKeyPair,
        X_other: OwnershipPublicKey,
    ) -> anyhow::Result<State0> {
        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(State0 {
            x_self,
            X_other,
            final_address_self,
            final_address_other,
            previous_balance,
            previous_TX_f,
            r_self: r,
            y_self: y,
            time_lock,
        })
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        self,
        Message0 {
            R: R_other,
            Y: Y_other,
        }: Message0,
    ) -> anyhow::Result<State1> {
        let previous_funding_txin = self.previous_TX_f.as_txin();
        let previous_funding_psbt = PartiallySignedTransaction::from_unsigned_tx(Transaction {
            version: 2,
            lock_time: 0,
            input: vec![previous_funding_txin],
            output: vec![],
        })
        .expect("Only fails if script_sig or witness is empty which is not the case.");

        let balance = Balance {
            ours: self.previous_balance.ours - Amount::from_sat(crate::TX_FEE / 2),
            theirs: self.previous_balance.theirs - Amount::from_sat(crate::TX_FEE / 2),
        };

        let TX_f = FundingTransaction::new(vec![previous_funding_psbt], [
            (self.x_self.public(), balance.ours),
            (self.X_other.clone(), balance.theirs),
        ])?;

        let sig_TX_f = TX_f.sign_once(self.x_self.clone(), &self.previous_TX_f);

        let TX_c = CommitTransaction::new(
            &TX_f,
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
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other.clone());

        let TX_s = SplitTransaction::new(&TX_c, [
            (balance.ours, self.final_address_self.clone()),
            (balance.theirs, self.final_address_other.clone()),
        ])?;
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(State1 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance,
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            previous_TX_f_output_descriptor: self.previous_TX_f.fund_output_descriptor(),
            TX_f,
            sig_TX_f,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        })
    }
}

#[derive(Debug)]
pub(crate) struct State1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    previous_TX_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    TX_f: FundingTransaction,
    sig_TX_f: Signature,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
}

impl State1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub fn receive(
        mut self,
        Message1 {
            sig_TX_s: sig_TX_s_other,
        }: Message1,
    ) -> anyhow::Result<State2> {
        self.TX_s
            .verify_sig(self.X_other.clone(), &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        self.TX_s.add_signatures(
            (self.x_self.public(), self.sig_TX_s_self),
            (self.X_other.clone(), sig_TX_s_other),
        )?;

        Ok(State2 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance: self.balance,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            previous_TX_f_output_descriptor: self.previous_TX_f_output_descriptor,
            TX_f: self.TX_f,
            sig_TX_f: self.sig_TX_f,
            TX_c: self.TX_c,
            signed_TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
        })
    }
}

#[derive(Debug)]
pub(crate) struct State2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    previous_TX_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    TX_f: FundingTransaction,
    sig_TX_f: Signature,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
}

impl State2 {
    pub fn next_message(&self) -> Message2 {
        Message2 {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message2 {
            encsig_TX_c: encsig_TX_c_other,
        }: Message2,
    ) -> anyhow::Result<State3> {
        self.TX_c
            .verify_encsig(
                self.X_other.clone(),
                self.y_self.public(),
                &encsig_TX_c_other,
            )
            .context("failed to verify encsig_TX_c sent by counterparty")?;

        Ok(State3 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance: self.balance,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            previous_TX_f_output_descriptor: self.previous_TX_f_output_descriptor,
            TX_f: self.TX_f,
            sig_TX_f: self.sig_TX_f,
            TX_c: self.TX_c,
            signed_TX_s: self.signed_TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other,
        })
    }
}

#[derive(Debug)]
pub(crate) struct State3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    previous_TX_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    TX_f: FundingTransaction,
    sig_TX_f: Signature,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
}

impl State3 {
    pub async fn next_message(&self) -> anyhow::Result<Message3> {
        Ok(Message3 {
            sig_TX_f: self.sig_TX_f.clone(),
        })
    }

    /// Returns the Channel and the transaction to broadcast.
    pub fn receive(
        self,
        Message3 {
            sig_TX_f: sig_TX_f_other,
        }: Message3,
    ) -> anyhow::Result<(Channel, Transaction)> {
        let signed_TX_f = self.TX_f.clone().add_signatures(
            self.previous_TX_f_output_descriptor,
            (self.x_self.public(), self.sig_TX_f),
            (self.X_other.clone(), sig_TX_f_other),
        )?;

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
