use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey},
    signature::verify_sig,
    transaction::{CloseTransaction, FundingTransaction, SplitTransaction},
    Channel,
};
use anyhow::Context;
use bitcoin::{Address, Transaction};
use ecdsa_fun::Signature;

pub struct State0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    TX_f: FundingTransaction,
    TX_s: SplitTransaction,
    final_address_self: Address,
}
pub struct State1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    TX_f: FundingTransaction,
    TX_s: SplitTransaction,
    final_address_self: Address,
    final_address_other: Address,
}

pub struct Message0 {
    final_address: Address,
}

#[derive(Debug)]
pub struct Message1 {
    sig_close_transaction: Signature,
}

impl State0 {
    pub fn new(channel: Channel, final_address_self: Address) -> Self {
        Self {
            x_self: channel.x_self,
            X_other: channel.X_other,
            final_address_self,
            TX_f: channel.TX_f_body,
            TX_s: channel.current_state.signed_TX_s,
        }
    }

    pub fn compose(&self) -> Message0 {
        Message0 {
            final_address: self.final_address_self.clone(),
        }
    }

    pub fn interpret(
        self,
        Message0 {
            final_address: final_address_other,
        }: Message0,
    ) -> State1 {
        State1 {
            x_self: self.x_self,
            X_other: self.X_other,
            TX_f: self.TX_f,
            TX_s: self.TX_s,
            final_address_self: self.final_address_self,
            final_address_other,
        }
    }
}

impl State1 {
    pub fn compose(&self) -> anyhow::Result<Message1> {
        let close_transaction = self.create_close_transaction()?;
        let sig_close_transaction = close_transaction.sign_once(self.x_self.clone());

        Ok(Message1 {
            sig_close_transaction,
        })
    }

    pub fn interpret(
        self,
        Message1 {
            sig_close_transaction: sig_close_transaction_other,
        }: Message1,
    ) -> anyhow::Result<Transaction> {
        let close_transaction = self.create_close_transaction()?;

        // in a real application we would double check the amounts
        verify_sig(
            self.X_other.clone(),
            &close_transaction.digest(),
            &sig_close_transaction_other,
        )
        .context("failed to verify close transaction sent by counterparty")?;

        let sig_close_transaction_self = close_transaction.sign_once(self.x_self.clone());
        let close_transaction = close_transaction.add_signatures(
            (self.x_self.public(), sig_close_transaction_self),
            (self.X_other, sig_close_transaction_other),
        )?;
        Ok(close_transaction)
    }

    fn create_close_transaction(&self) -> anyhow::Result<CloseTransaction> {
        let (amount_a, X_a) = self.TX_s.outputs().a;
        let (amount_b, X_b) = self.TX_s.outputs().b;

        let (output_a, output_b) = if X_a == self.x_self.public() {
            (
                (amount_a, self.final_address_self.clone()),
                (amount_b, self.final_address_other.clone()),
            )
        } else if X_b == self.x_self.public() {
            (
                (amount_a, self.final_address_other.clone()),
                (amount_b, self.final_address_self.clone()),
            )
        } else {
            anyhow::bail!("No valid output found")
        };

        Ok(CloseTransaction::new(&self.TX_f, output_a, output_b))
    }
}
