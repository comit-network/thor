use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey},
    protocols::Result,
    transaction::{CloseTransaction, FundingTransaction},
    Balance, Channel, Error,
};
use bitcoin::{Address, Transaction};
use ecdsa_fun::Signature;

#[derive(Debug)]
pub struct State0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    TX_f: FundingTransaction,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
            balance: channel.balance(),
            final_address_self: channel.final_address_self.clone(),
            final_address_other: channel.final_address_other.clone(),
        }
    }

    pub fn compose(&self) -> Result<Message0> {
        let close_transaction = CloseTransaction::new(&self.TX_f, [
            (self.balance.ours, self.final_address_self.clone()),
            (self.balance.theirs, self.final_address_other.clone()),
        ])?;
        let sig_close_transaction = close_transaction.sign_once(self.x_self.clone());

        Ok(Message0 {
            sig_close_transaction,
        })
    }

    pub fn interpret(
        self,
        Message0 {
            sig_close_transaction: sig_close_transaction_other,
        }: Message0,
    ) -> Result<Transaction> {
        let close_transaction = CloseTransaction::new(&self.TX_f, [
            (self.balance.ours, self.final_address_self),
            (self.balance.theirs, self.final_address_other),
        ])?;

        close_transaction
            .verify_sig(self.X_other.clone(), &sig_close_transaction_other)
            .map_err(Error::CloseTransactionSignature)?;

        let sig_close_transaction_self = close_transaction.sign_once(self.x_self.clone());
        let close_transaction = close_transaction.add_signatures(
            (self.x_self.public(), sig_close_transaction_self),
            (self.X_other, sig_close_transaction_other),
        )?;

        Ok(close_transaction)
    }
}
