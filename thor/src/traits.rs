use crate::Message;
use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount, Transaction};

#[async_trait::async_trait]
pub trait NewAddress {
    async fn new_address(&self) -> anyhow::Result<Address>;
}

#[async_trait::async_trait]
pub trait BroadcastSignedTransaction {
    async fn broadcast_signed_transaction(&self, transaction: Transaction) -> anyhow::Result<()>;
}

/// Sign one of the inputs of the `FundingTransaction`.
#[async_trait::async_trait]
pub trait SignFundingPSBT {
    type Error: std::fmt::Display;

    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, Self::Error>;
}

#[async_trait::async_trait]
pub trait BuildFundingPSBT {
    type Error: std::fmt::Display;

    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> Result<PartiallySignedTransaction, Self::Error>;
}

#[async_trait::async_trait]
pub trait SendMessage {
    async fn send_message(&mut self, message: Message) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
pub trait ReceiveMessage {
    async fn receive_message(&mut self) -> anyhow::Result<Message>;
}
