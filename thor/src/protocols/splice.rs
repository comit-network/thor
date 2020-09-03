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
use async_trait::async_trait;
use bitcoin::{
    consensus::serialize, util::psbt::PartiallySignedTransaction, Address, Amount, Transaction,
    TxOut,
};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
    #[cfg_attr(feature = "serde", serde(default))]
    splice_in: Option<SpliceIn>,
    #[cfg_attr(feature = "serde", serde(default))]
    splice_out: Option<TxOut>,
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
    splice_transaction_signature: Signature,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction::option")
    )]
    signed_splice_transaction: Option<PartiallySignedTransaction>,
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
    splice_in_self: Option<SpliceIn>,
    splice_out_self: Option<TxOut>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct SpliceIn {
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
    pub amount: Amount,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction")
    )]
    pub input_psbt: PartiallySignedTransaction,
}

#[async_trait]
pub trait BuildSplicePsbt {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> Result<PartiallySignedTransaction>;
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
        splice_in_self: Option<Amount>,
        splice_out_self: Option<TxOut>,
        wallet: &W,
    ) -> Result<State0>
    where
        W: BuildFundingPsbt,
    {
        // TODO: Prevent the same party to splice-in and out in the same transaction
        if let Some(ref tx_out) = splice_out_self {
            if tx_out.value > previous_balance.ours.as_sat() {
                anyhow::bail!("Not enough balance to splice out {} sats", tx_out.value)
            }
        }

        let splice_in_self = match splice_in_self {
            Some(amount) => {
                let fund_output = FundOutput::new([x_self.public(), X_other.clone()]);
                let input_psbt = wallet
                    .build_funding_psbt(fund_output.address(), amount)
                    .await?;
                Some(SpliceIn { input_psbt, amount })
            }
            None => None,
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
            splice_in_self,
            splice_out_self,
            time_lock,
        })
    }

    pub fn compose(&self) -> Message0 {
        Message0 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
            splice_in: self.splice_in_self.clone(),
            splice_out: self.splice_out_self.clone(),
        }
    }

    pub fn interpret(
        self,
        Message0 {
            R: R_other,
            Y: Y_other,
            splice_in: splice_in_other,
            splice_out: splice_out_other,
        }: Message0,
    ) -> Result<State1> {
        let mut our_balance = self.previous_balance.ours;
        let mut their_balance = self.previous_balance.theirs;

        // TODO: Prevent the same party to splice-in and out in the same transaction
        let mut splice_outputs = vec![];
        if let Some(tx_out) = splice_out_other {
            if tx_out.value > self.previous_balance.theirs.as_sat() {
                anyhow::bail!("Counterpart is splicing out more than they have");
            } else {
                // Need to pay the transaction fee, taking it out of the splice out.
                // TODO: split between splice in and splice out if there is both
                their_balance -= Amount::from_sat(tx_out.value) + Amount::from_sat(TX_FEE);
                splice_outputs.push(tx_out);
            }
        }

        if let Some(tx_out) = self.splice_out_self {
            if tx_out.value > self.previous_balance.ours.as_sat() {
                anyhow::bail!("We are splicing out more than we have");
            } else {
                our_balance -= Amount::from_sat(tx_out.value) + Amount::from_sat(TX_FEE);
                splice_outputs.push(tx_out);
            }
        }

        let previous_funding_txin = self.previous_tx_f.as_txin();
        let previous_funding_psbt = PartiallySignedTransaction::from_unsigned_tx(Transaction {
            version: 2,
            lock_time: 0,
            input: vec![previous_funding_txin],
            output: vec![],
        })
        .expect("Only fails if script_sig or witness is empty which is not the case.");

        let mut splice_in_inputs = vec![];

        if let Some(splice_in) = self.splice_in_self.clone() {
            splice_in_inputs.push(splice_in.input_psbt);
            our_balance += splice_in.amount;
        }

        if let Some(splice_in) = splice_in_other {
            splice_in_inputs.push(splice_in.input_psbt);
            their_balance += splice_in.amount;
        }

        // Sort the Psbt inputs based on the ascending lexicographical order of
        // bytes of their consensus serialization. Both parties _must_ do this so that
        // they compute the same splice transaction.
        splice_in_inputs.sort_by(|a, b| {
            serialize(a)
                .partial_cmp(&serialize(b))
                .expect("comparison is possible")
        });

        // The previous funding psbt MUST be the first input
        let mut inputs = vec![previous_funding_psbt];

        inputs.append(&mut splice_in_inputs);

        let balance = Balance {
            ours: our_balance,
            theirs: their_balance,
        };

        let tx_f = SpliceTransaction::new(inputs, splice_outputs, [
            (self.x_self.public(), balance.ours),
            (self.X_other.clone(), balance.theirs),
        ])?;

        // TODO: Clean-up the signature/Psbt mix (if possible)

        // Signed to spend tx_f
        let sig_tx_f = tx_f.sign_once(self.x_self.clone(), &self.previous_tx_f);

        let tx_c = CommitTransaction::new(
            &tx_f.clone().into(),
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
        let encsig_tx_c_self = tx_c.encsign_once(&self.x_self, Y_other.clone());

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
        let sig_tx_s_self = tx_s.sign_once(&self.x_self);

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
            splice_transaction: tx_f,
            splice_transaction_signature: sig_tx_f,
            tx_c,
            tx_s,
            encsig_tx_c_self,
            sig_tx_s_self,
            splice_in_self: self.splice_in_self,
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
    splice_transaction_signature: Signature,
    tx_c: CommitTransaction,
    tx_s: SplitTransaction,
    encsig_tx_c_self: EncryptedSignature,
    sig_tx_s_self: Signature,
    splice_in_self: Option<SpliceIn>,
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
            splice_transaction_signature: self.splice_transaction_signature,
            tx_c: self.tx_c,
            signed_tx_s: self.tx_s,
            encsig_tx_c_self: self.encsig_tx_c_self,
            splice_in_self: self.splice_in_self,
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
    splice_transaction_signature: Signature,
    tx_c: CommitTransaction,
    signed_tx_s: SplitTransaction,
    encsig_tx_c_self: EncryptedSignature,
    splice_in_self: Option<SpliceIn>,
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
        let signed_splice_transaction = match self.splice_in_self {
            Some(_) => Some(
                wallet
                    .sign_funding_psbt(self.splice_transaction.clone().into_psbt()?)
                    .await?,
            ),
            None => None,
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
            splice_transaction_signature: self.splice_transaction_signature,
            tx_c: self.tx_c,
            signed_tx_s: self.signed_tx_s,
            encsig_tx_c_self: self.encsig_tx_c_self,
            encsig_tx_c_other,
            signed_splice_transaction,
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
    splice_transaction_signature: Signature,
    tx_c: CommitTransaction,
    signed_tx_s: SplitTransaction,
    encsig_tx_c_self: EncryptedSignature,
    encsig_tx_c_other: EncryptedSignature,
    signed_splice_transaction: Option<PartiallySignedTransaction>,
}

impl State3 {
    pub async fn compose(&self) -> Result<Message3> {
        Ok(Message3 {
            splice_transaction_signature: self.splice_transaction_signature.clone(),
            signed_splice_transaction: self.signed_splice_transaction.clone(),
        })
    }

    /// Returns the Channel and the transaction to broadcast.
    pub async fn interpret(
        self,
        Message3 {
            splice_transaction_signature: splice_transaction_signature_other,
            signed_splice_transaction: signed_splice_transaction_other,
        }: Message3,
        wallet: &impl SignFundingPsbt,
    ) -> Result<(Channel, Transaction)> {
        // TODO: Check that the received splice transaction is the same than we expect
        // If the other party sent a splice-in signed tx_f, use it, otherwise, use our
        // unsigned tx_f
        let splice_transaction = match signed_splice_transaction_other {
            Some(signed_splice_transaction_other) => signed_splice_transaction_other,
            None => self.splice_transaction.clone().into_psbt()?,
        };

        // If we have a splice-in input, we need to sign it, otherwise, use the previous
        // tx_f
        let splice_transaction = match self.signed_splice_transaction {
            Some(_) => wallet.sign_funding_psbt(splice_transaction).await?,
            None => splice_transaction,
        };

        // Add the signatures to spend the previous tx_f
        let splice_transaction = add_signatures(
            splice_transaction.extract_tx(),
            self.previous_tx_f_output_descriptor,
            (self.x_self.public(), self.splice_transaction_signature),
            (self.X_other.clone(), splice_transaction_signature_other),
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

pub fn add_signatures(
    mut transaction: Transaction,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
    (X_0, sig_0): (OwnershipPublicKey, Signature),
    (X_1, sig_1): (OwnershipPublicKey, Signature),
) -> Result<Transaction> {
    let satisfier = {
        let mut satisfier = HashMap::with_capacity(2);

        let X_0 = ::bitcoin::PublicKey {
            compressed: true,
            key: X_0.into(),
        };
        let X_1 = ::bitcoin::PublicKey {
            compressed: true,
            key: X_1.into(),
        };

        // The order in which these are inserted doesn't matter
        satisfier.insert(X_0, (sig_0.into(), ::bitcoin::SigHashType::All));
        satisfier.insert(X_1, (sig_1.into(), ::bitcoin::SigHashType::All));

        satisfier
    };

    input_descriptor.satisfy(&mut transaction.input[0], satisfier)?;

    Ok(transaction)
}
