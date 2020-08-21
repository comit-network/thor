use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey},
    signature::verify_sig,
    transaction::{CloseTransaction, FundingTransaction, SplitTransaction},
    Channel,
};
use anyhow::Context;
use bitcoin::Transaction;
use ecdsa_fun::Signature;

pub struct State0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    TX_f: FundingTransaction,
    TX_s: SplitTransaction,
}

#[derive(Debug)]
pub struct Message0 {
    sig_close_transaction: Signature,
}

impl State0 {
    pub fn new(channel: &Channel) -> Self {
        Self {
            x_self: channel.x_self.clone(),
            X_other: channel.X_other.clone(),
            TX_f: channel.TX_f_body.clone(),
            TX_s: channel.current_state.signed_TX_s.clone(),
        }
    }

    pub fn compose(&self) -> Message0 {
        let close_transaction = CloseTransaction::new(&self.TX_f, &self.TX_s);
        let sig_close_transaction = close_transaction.sign_once(self.x_self.clone());

        Message0 {
            sig_close_transaction,
        }
    }

    pub fn interpret(
        self,
        Message0 {
            sig_close_transaction: sig_close_transaction_other,
        }: Message0,
    ) -> anyhow::Result<Transaction> {
        let close_transaction = CloseTransaction::new(&self.TX_f, &self.TX_s);

        verify_sig(
            self.X_other.clone(),
            &close_transaction.digest(),
            &sig_close_transaction_other,
        )
        .context("failed to verify close transaction signature sent by counterparty")?;

        let sig_close_transaction_self = close_transaction.sign_once(self.x_self.clone());
        let close_transaction = close_transaction.add_signatures(
            (self.x_self.public(), sig_close_transaction_self),
            (self.X_other, sig_close_transaction_other),
        )?;

        Ok(close_transaction)
    }
}
