use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    transaction::{
        CommitTransaction, FundOutput, FundingTransaction, SpliceTransaction, SplitTransaction,
    },
    Balance, BuildFundingPSBT, Channel, ChannelState, SignFundingPSBT, SplitOutput,
    StandardChannelState,
};
use anyhow::Context;
use bitcoin::{
    consensus::serialize, util::psbt::PartiallySignedTransaction, Address, Amount, Transaction,
};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use miniscript::Descriptor;
use std::collections::HashMap;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
    #[cfg_attr(feature = "serde", serde(default))]
    splice_in: Option<SpliceIn>,
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
    previous_TX_f: FundingTransaction,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    splice_in_self: Option<SpliceIn>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

#[async_trait::async_trait]
pub trait BuildSplicePSBT {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> anyhow::Result<PartiallySignedTransaction>;
}

impl State0 {
    #[allow(clippy::too_many_arguments)]
    pub async fn new<W>(
        time_lock: u32,
        final_address_self: Address,
        final_address_other: Address,
        previous_balance: Balance,
        previous_TX_f: FundingTransaction,
        x_self: OwnershipKeyPair,
        X_other: OwnershipPublicKey,
        splice_in: Option<Amount>,
        wallet: &W,
    ) -> anyhow::Result<State0>
    where
        W: BuildFundingPSBT,
    {
        let splice_in_self = match splice_in {
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
            previous_TX_f,
            r_self: r,
            y_self: y,
            splice_in_self,
            time_lock,
        })
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
            splice_in: self.splice_in_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message0 {
            R: R_other,
            Y: Y_other,
            splice_in: splice_in_other,
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

        let mut our_balance = self.previous_balance.ours;
        let mut their_balance = self.previous_balance.theirs;

        let mut splice_in_inputs = vec![];

        if let Some(splice_in) = self.splice_in_self.clone() {
            splice_in_inputs.push(splice_in.input_psbt);
            our_balance += splice_in.amount;
        }

        if let Some(splice_in) = splice_in_other {
            splice_in_inputs.push(splice_in.input_psbt);
            their_balance += splice_in.amount;
        }

        // Sort the PSBT inputs based on the ascending lexicographical order of
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

        let TX_f = SpliceTransaction::new(inputs, [
            (self.x_self.public(), balance.ours),
            (self.X_other.clone(), balance.theirs),
        ])?;

        // TODO: Clean-up the signature/PSBT mix (if possible)

        // Signed to spend TX_f
        let sig_TX_f = TX_f.sign_once(self.x_self.clone(), &self.previous_TX_f);

        let TX_c = CommitTransaction::new(
            &TX_f.clone().into(),
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
        let encsig_TX_c_self = TX_c.encsign_once(&self.x_self, Y_other.clone());

        let TX_s = SplitTransaction::new(&TX_c, vec![
            SplitOutput::Balance {
                amount: balance.ours,
                address: self.final_address_self.clone(),
            },
            SplitOutput::Balance {
                amount: balance.theirs,
                address: self.final_address_other.clone(),
            },
        ])?;
        let sig_TX_s_self = TX_s.sign_once(&self.x_self);

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
            splice_transaction: TX_f,
            splice_transaction_signature: sig_TX_f,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
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
    previous_TX_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    splice_transaction: SpliceTransaction,
    splice_transaction_signature: Signature,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
    splice_in_self: Option<SpliceIn>,
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
            splice_transaction: self.splice_transaction,
            splice_transaction_signature: self.splice_transaction_signature,
            TX_c: self.TX_c,
            signed_TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
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
    previous_TX_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    splice_transaction: SpliceTransaction,
    splice_transaction_signature: Signature,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    splice_in_self: Option<SpliceIn>,
}

impl State2 {
    pub fn next_message(&self) -> Message2 {
        Message2 {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub async fn receive(
        self,
        Message2 {
            encsig_TX_c: encsig_TX_c_other,
        }: Message2,
        wallet: &impl SignFundingPSBT,
    ) -> anyhow::Result<State3> {
        self.TX_c
            .verify_encsig(
                self.X_other.clone(),
                self.y_self.public(),
                &encsig_TX_c_other,
            )
            .context("failed to verify encsig_TX_c sent by counterparty")?;

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
            previous_TX_f_output_descriptor: self.previous_TX_f_output_descriptor,
            splice_transaction: self.splice_transaction,
            splice_transaction_signature: self.splice_transaction_signature,
            TX_c: self.TX_c,
            signed_TX_s: self.signed_TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other,
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
    previous_TX_f_output_descriptor: Descriptor<bitcoin::PublicKey>,
    splice_transaction: SpliceTransaction,
    splice_transaction_signature: Signature,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
    signed_splice_transaction: Option<PartiallySignedTransaction>,
}

impl State3 {
    pub async fn next_message(&self) -> anyhow::Result<Message3> {
        Ok(Message3 {
            splice_transaction_signature: self.splice_transaction_signature.clone(),
            signed_splice_transaction: self.signed_splice_transaction.clone(),
        })
    }

    /// Returns the Channel and the transaction to broadcast.
    pub async fn receive(
        self,
        Message3 {
            splice_transaction_signature: splice_transaction_signature_other,
            signed_splice_transaction: signed_splice_transaction_other,
        }: Message3,
        wallet: &impl SignFundingPSBT,
    ) -> anyhow::Result<(Channel, Transaction)> {
        // TODO: Check that the received splice transaction is the same than we expect
        // If the other party sent a splice-in signed TX_f, use it, otherwise, use our
        // unsigned TX_f
        let splice_transaction = match signed_splice_transaction_other {
            Some(signed_splice_transaction_other) => signed_splice_transaction_other,
            None => self.splice_transaction.clone().into_psbt()?,
        };

        // If we have a splice-in input, we need to sign it, otherwise, use the previous
        // TX_f
        let splice_transaction = match self.signed_splice_transaction {
            Some(_) => wallet.sign_funding_psbt(splice_transaction).await?,
            None => splice_transaction,
        };

        // Add the signatures to spend the previous TX_f
        let splice_transaction = add_signatures(
            splice_transaction.extract_tx(),
            self.previous_TX_f_output_descriptor,
            (self.x_self.public(), self.splice_transaction_signature),
            (self.X_other.clone(), splice_transaction_signature_other),
        )?;

        Ok((
            Channel {
                x_self: self.x_self,
                X_other: self.X_other,
                final_address_self: self.final_address_self,
                final_address_other: self.final_address_other,
                TX_f_body: self.splice_transaction.into(),
                current_state: ChannelState::Standard(StandardChannelState {
                    balance: self.balance,
                    TX_c: self.TX_c,
                    encsig_TX_c_other: self.encsig_TX_c_other,
                    r_self: self.r_self,
                    R_other: self.R_other,
                    y_self: self.y_self,
                    Y_other: self.Y_other,
                    signed_TX_s: self.signed_TX_s,
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
) -> anyhow::Result<Transaction> {
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
