use crate::{
    channel::Channel,
    keys::{OwnershipKeyPair, OwnershipPublicKey},
    transaction::{CloseTransaction, FundingTransaction},
    Balance,
};
use anyhow::{Context, Result};
use bitcoin::{Address, Transaction};
use ecdsa_fun::Signature;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub(crate) struct State0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tx_f: FundingTransaction,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    close_tx: CloseTransaction,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    sig_close_transaction: Signature,
}

impl State0 {
    pub(crate) fn new(channel: &Channel) -> Result<Self> {
        let Balance { ours, theirs } = channel.balance();
        let addr_ours = channel.final_address_self.clone();
        let addr_theirs = channel.final_address_other.clone();
        let tx_f = channel.tx_f_body.clone();

        let tx = CloseTransaction::new(&tx_f, [(ours, addr_ours), (theirs, addr_theirs)])?;

        Ok(Self {
            x_self: channel.x_self.clone(),
            X_other: channel.X_other.clone(),
            tx_f,
            balance: channel.balance(),
            final_address_self: channel.final_address_self.clone(),
            final_address_other: channel.final_address_other.clone(),
            close_tx: tx,
        })
    }

    pub(crate) fn compose(&self) -> Message0 {
        let sig_close_transaction = self.close_tx.sign(&self.x_self);

        Message0 {
            sig_close_transaction,
        }
    }

    pub(crate) fn interpret(
        self,
        Message0 {
            sig_close_transaction: sig_close_transaction_other,
        }: Message0,
    ) -> Result<Transaction> {
        let close_transaction = self.close_tx;

        close_transaction
            .verify_sig(self.X_other.clone(), &sig_close_transaction_other)
            .context("failed to verify close transaction signature sent by counterparty")?;

        let sig_close_transaction_self = close_transaction.sign(&self.x_self);
        let close_transaction = close_transaction.add_signatures(
            (self.x_self.public(), sig_close_transaction_self),
            (self.X_other, sig_close_transaction_other),
        )?;

        Ok(close_transaction)
    }
}
