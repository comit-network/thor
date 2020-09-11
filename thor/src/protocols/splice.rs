use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    transaction::{
        CommitTransaction, FundOutput, FundingTransaction, SpliceTransaction, SplitTransaction,
    },
    Balance, BuildFundingPsbt, Channel, ChannelState, SignFundingPsbt, SplitOutput,
    StandardChannelState, TX_FEE,
};
use anyhow::{Context, Result};
use bitcoin::{
    consensus::serialize, util::psbt::PartiallySignedTransaction, Address, Amount, Transaction,
    TxOut,
};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
    #[cfg_attr(feature = "serde", serde(default))]
    splice: Splice,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message1 {
    sig_tx_s: Signature,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message2 {
    encsig_tx_c: EncryptedSignature,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message3 {
    sig_TX_splice_TX_f_input: Signature,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction::option")
    )]
    signed_TX_splice_psbt_input: Option<PartiallySignedTransaction>,
}

#[derive(Clone, Debug)]
pub(crate) struct State0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    previous_balance: Balance,
    previous_tx_f: FundingTransaction,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    splice_self: Splice,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub(crate) enum Splice {
    In {
        #[cfg_attr(
            feature = "serde",
            serde(with = "bitcoin::util::amount::serde::as_sat")
        )]
        amount: Amount,
        #[cfg_attr(
            feature = "serde",
            serde(with = "crate::serde::partially_signed_transaction")
        )]
        input_psbt: PartiallySignedTransaction,
    },
    Out(TxOut),
    None,
}

impl Default for Splice {
    fn default() -> Self {
        Splice::None
    }
}

impl State0 {
    #[allow(clippy::too_many_arguments)]
    pub async fn new<W>(
        time_lock: u32,
        final_address_self: Address,
        final_address_other: Address,
        previous_balance: Balance,
        previous_tx_f: FundingTransaction,
        x_self: OwnershipKeyPair,
        X_other: OwnershipPublicKey,
        splice_self: crate::Splice,
        wallet: &W,
    ) -> Result<State0>
    where
        W: BuildFundingPsbt,
    {
        let splice_self = match splice_self {
            crate::Splice::Out(tx_out) => {
                if tx_out.value > previous_balance.ours.as_sat() {
                    anyhow::bail!("Not enough balance to splice out {} sats", tx_out.value)
                }
                Splice::Out(tx_out)
            }
            crate::Splice::In(amount) => {
                let fund_output = FundOutput::new([x_self.public(), X_other.clone()]);
                let input_psbt = wallet
                    .build_funding_psbt(fund_output.address(), amount)
                    .await?;
                Splice::In { input_psbt, amount }
            }
            crate::Splice::None => Splice::None,
        };

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(State0 {
            x_self,
            X_other,
            final_address_self,
            final_address_other,
            previous_balance,
            previous_tx_f,
            r_self: r,
            y_self: y,
            splice_self,
            time_lock,
        })
    }

    pub fn compose(&self) -> Message0 {
        Message0 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
            splice: self.splice_self.clone(),
        }
    }

    pub fn interpret(
        self,
        Message0 {
            R: R_other,
            Y: Y_other,
            splice: splice_other,
        }: Message0,
    ) -> Result<State1> {
        let mut our_balance = self.previous_balance.ours;
        let mut their_balance = self.previous_balance.theirs;

        let mut splice_outputs = vec![];
        let mut splice_in_inputs = vec![];

        match self.splice_self.clone() {
            Splice::Out(tx_out) => {
                if tx_out.value > self.previous_balance.ours.as_sat() {
                    anyhow::bail!("We are splicing out more than we have");
                } else {
                    our_balance -= Amount::from_sat(tx_out.value) + Amount::from_sat(TX_FEE);
                    splice_outputs.push(tx_out);
                }
            }
            Splice::In { amount, input_psbt } => {
                splice_in_inputs.push(input_psbt);
                our_balance += amount;
            }
            Splice::None => (),
        }

        match splice_other {
            Splice::Out(tx_out) => {
                if tx_out.value > self.previous_balance.theirs.as_sat() {
                    anyhow::bail!("Counterpart is splicing out more than they have");
                } else {
                    // Need to pay the transaction fee, taking it out of the splice out.
                    // TODO: split between splice in and splice out if there is both
                    their_balance -= Amount::from_sat(tx_out.value) + Amount::from_sat(TX_FEE);
                    splice_outputs.push(tx_out);
                }
            }
            Splice::In { amount, input_psbt } => {
                splice_in_inputs.push(input_psbt);
                their_balance += amount;
            }
            Splice::None => (),
        }

        // Sort the PSBT inputs based on the ascending lexicographical order of
        // bytes of their consensus serialization. Both parties _must_ do this so that
        // they compute the same splice transaction.
        splice_in_inputs.sort_by(|a, b| {
            serialize(a)
                .partial_cmp(&serialize(b))
                .expect("comparison is possible")
        });

        let previous_funding_txin = self.previous_tx_f.as_txin();
        let previous_funding_psbt = PartiallySignedTransaction::from_unsigned_tx(Transaction {
            version: 2,
            lock_time: 0,
            input: vec![previous_funding_txin],
            output: vec![],
        })
        .expect("Only fails if script_sig or witness is empty which is not the case.");

        // The previous funding psbt MUST be the first input
        let mut inputs = vec![previous_funding_psbt];

        inputs.append(&mut splice_in_inputs);

        let balance = Balance {
            ours: our_balance,
            theirs: their_balance,
        };

        let splice_transaction = SpliceTransaction::new(inputs, splice_outputs, [
            (self.x_self.public(), balance.ours),
            (self.X_other.clone(), balance.theirs),
        ])?;

        // Signed to spend TX_f
        let sig_TX_splice_TX_f_input =
            splice_transaction.sign(self.x_self.clone(), &self.previous_tx_f);

        let tx_c = CommitTransaction::new(
            &splice_transaction.clone().into(),
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
        let encsig_tx_c_self = tx_c.encsign(&self.x_self, Y_other.clone());

        let tx_s = SplitTransaction::new(&tx_c, vec![
            SplitOutput::Balance {
                amount: balance.ours,
                address: self.final_address_self.clone(),
            },
            SplitOutput::Balance {
                amount: balance.theirs,
                address: self.final_address_other.clone(),
            },
        ])?;
        let sig_tx_s_self = tx_s.sign(&self.x_self);

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
            previous_tx_f_output_descriptor: self.previous_tx_f.fund_output_descriptor(),
            splice_transaction,
            sig_TX_splice_TX_f_input,
            tx_c,
            tx_s,
            encsig_tx_c_self,
            sig_tx_s_self,
            splice_self: self.splice_self,
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
    previous_tx_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    splice_transaction: SpliceTransaction,
    sig_TX_splice_TX_f_input: Signature,
    tx_c: CommitTransaction,
    tx_s: SplitTransaction,
    encsig_tx_c_self: EncryptedSignature,
    sig_tx_s_self: Signature,
    splice_self: Splice,
}

impl State1 {
    pub fn compose(&self) -> Message1 {
        Message1 {
            sig_tx_s: self.sig_tx_s_self.clone(),
        }
    }

    pub fn interpret(
        mut self,
        Message1 {
            sig_tx_s: sig_tx_s_other,
        }: Message1,
    ) -> Result<State2> {
        self.tx_s
            .verify_sig(self.X_other.clone(), &sig_tx_s_other)
            .context("failed to verify sig_tx_s sent by counterparty")?;

        self.tx_s.add_signatures(
            (self.x_self.public(), self.sig_tx_s_self),
            (self.X_other.clone(), sig_tx_s_other),
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
            previous_tx_f_output_descriptor: self.previous_tx_f_output_descriptor,
            splice_transaction: self.splice_transaction,
            sig_TX_splice_TX_f_input: self.sig_TX_splice_TX_f_input,
            tx_c: self.tx_c,
            signed_tx_s: self.tx_s,
            encsig_tx_c_self: self.encsig_tx_c_self,
            splice_self: self.splice_self,
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
    previous_tx_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    splice_transaction: SpliceTransaction,
    sig_TX_splice_TX_f_input: Signature,
    tx_c: CommitTransaction,
    signed_tx_s: SplitTransaction,
    encsig_tx_c_self: EncryptedSignature,
    splice_self: Splice,
}

impl State2 {
    pub fn compose(&self) -> Message2 {
        Message2 {
            encsig_tx_c: self.encsig_tx_c_self.clone(),
        }
    }

    pub async fn interpret(
        self,
        Message2 {
            encsig_tx_c: encsig_tx_c_other,
        }: Message2,
        wallet: &impl SignFundingPsbt,
    ) -> Result<State3> {
        self.tx_c
            .verify_encsig(
                self.X_other.clone(),
                self.y_self.public(),
                &encsig_tx_c_other,
            )
            .context("failed to verify encsig_tx_c sent by counterparty")?;

        // Signed to spend the splice-in input
        let signed_TX_splice_psbt_self_input = match self.splice_self {
            Splice::In { .. } => Some(
                wallet
                    .sign_funding_psbt(self.splice_transaction.clone().into_psbt()?)
                    .await?,
            ),
            _ => None,
        };

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
            previous_tx_f_output_descriptor: self.previous_tx_f_output_descriptor,
            splice_transaction: self.splice_transaction,
            sig_TX_splice_TX_f_input: self.sig_TX_splice_TX_f_input,
            tx_c: self.tx_c,
            signed_tx_s: self.signed_tx_s,
            encsig_tx_c_self: self.encsig_tx_c_self,
            encsig_tx_c_other,
            signed_TX_splice_psbt_self_input,
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
    previous_tx_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    splice_transaction: SpliceTransaction,
    sig_TX_splice_TX_f_input: Signature,
    tx_c: CommitTransaction,
    signed_tx_s: SplitTransaction,
    encsig_tx_c_self: EncryptedSignature,
    encsig_tx_c_other: EncryptedSignature,
    signed_TX_splice_psbt_self_input: Option<PartiallySignedTransaction>,
}

impl State3 {
    pub async fn compose(&self) -> Result<Message3> {
        Ok(Message3 {
            sig_TX_splice_TX_f_input: self.sig_TX_splice_TX_f_input.clone(),
            signed_TX_splice_psbt_input: self.signed_TX_splice_psbt_self_input.clone(),
        })
    }

    /// Returns the Channel and the transaction to broadcast.
    pub async fn interpret(
        self,
        Message3 {
            sig_TX_splice_TX_f_input: sig_TX_splice_TX_f_input_other,
            signed_TX_splice_psbt_input: signed_TX_splice_psbt_input_other,
        }: Message3,
        wallet: &impl SignFundingPsbt,
    ) -> Result<(Channel, Transaction)> {
        // TODO: Check that the received splice transaction is the same than we expect
        // If the other party sent a splice-in signed tx_f, use it, otherwise, use our
        // unsigned tx_f
        let splice_transaction = match signed_TX_splice_psbt_input_other {
            Some(signed_splice_transaction_other) => signed_splice_transaction_other,
            None => self.splice_transaction.clone().into_psbt()?,
        };

        // If we have a splice-in input, we need to sign it, otherwise, use the previous
        // tx_f
        let splice_transaction = match self.signed_TX_splice_psbt_self_input {
            Some(_) => wallet.sign_funding_psbt(splice_transaction).await?,
            None => splice_transaction,
        };

        // Add the signatures to spend the previous tx_f
        let splice_transaction = SpliceTransaction::add_signatures(
            splice_transaction.extract_tx(),
            self.previous_tx_f_output_descriptor,
            (self.x_self.public(), self.sig_TX_splice_TX_f_input),
            (self.X_other.clone(), sig_TX_splice_TX_f_input_other),
        )?;

        Ok((
            Channel {
                x_self: self.x_self,
                X_other: self.X_other,
                final_address_self: self.final_address_self,
                final_address_other: self.final_address_other,
                tx_f_body: self.splice_transaction.into(),
                current_state: ChannelState::Standard(StandardChannelState {
                    balance: self.balance,
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
            splice_transaction,
        ))
    }
}
