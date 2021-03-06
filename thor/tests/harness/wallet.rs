use thor::{
    channel::{BroadcastSignedTransaction, BuildFundingPsbt, NewAddress, SignFundingPsbt},
    GetRawTransaction, MedianTime,
};

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount};
use bitcoin_harness::{bitcoind_rpc::PsbtBase64, Bitcoind};
use reqwest::Url;
use std::time::Duration;
use tokio::time;

#[derive(Debug)]
pub struct Wallet(pub bitcoin_harness::Wallet);

impl Wallet {
    async fn new(name: &str, url: Url) -> Result<Self> {
        let wallet = bitcoin_harness::Wallet::new(name, url).await?;

        Ok(Self(wallet))
    }

    pub async fn balance(&self) -> Result<Amount> {
        let balance = self.0.balance().await?;
        Ok(balance)
    }
}

/// Create two bitcoind wallets on the node passed as an argument and fund them
/// with the amount that they will contribute to the channel, plus a buffer to
/// account for transaction fees.
pub async fn make_wallets(
    bitcoind: &Bitcoind<'_>,
    fund_amount: Amount,
) -> Result<(Wallet, Wallet)> {
    let alice = make_wallet("alice", bitcoind, fund_amount).await?;
    let bob = make_wallet("bob", bitcoind, fund_amount).await?;

    Ok((alice, bob))
}

async fn make_wallet(name: &str, bitcoind: &Bitcoind<'_>, fund_amount: Amount) -> Result<Wallet> {
    let wallet = Wallet::new(name, bitcoind.node_url.clone()).await?;
    let buffer = Amount::from_btc(1.0).unwrap();
    let amount = fund_amount + buffer;

    let address = wallet.0.new_address().await.unwrap();

    bitcoind.mint(address, amount).await.unwrap();

    Ok(wallet)
}

#[async_trait]
impl BuildFundingPsbt for Wallet {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> Result<PartiallySignedTransaction> {
        let psbt = self.0.fund_psbt(output_address, output_amount).await?;
        let as_hex = base64::decode(psbt)?;

        let psbt = bitcoin::consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}

#[async_trait]
impl SignFundingPsbt for Wallet {
    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction> {
        let psbt = bitcoin::consensus::serialize(&psbt);
        let as_base64 = base64::encode(psbt);

        let psbt = self.0.wallet_process_psbt(PsbtBase64(as_base64)).await?;
        let PsbtBase64(signed_psbt) = PsbtBase64::from(psbt);

        let as_hex = base64::decode(signed_psbt)?;
        let psbt = bitcoin::consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}

#[async_trait]
impl BroadcastSignedTransaction for Wallet {
    async fn broadcast_signed_transaction(&self, transaction: bitcoin::Transaction) -> Result<()> {
        let _txid = self.0.send_raw_transaction(transaction).await?;

        // TODO: Instead of guessing how long it will take for the transaction to be
        // mined we should ask bitcoind for the number of confirmations on `txid`

        // give time for transaction to be mined
        time::delay_for(Duration::from_millis(1100)).await;

        Ok(())
    }
}

#[async_trait]
impl NewAddress for Wallet {
    async fn new_address(&self) -> Result<Address> {
        self.0.new_address().await.map_err(Into::into)
    }
}

#[async_trait]
impl MedianTime for Wallet {
    async fn median_time(&self) -> Result<u32> {
        self.0.median_time().await.map_err(Into::into)
    }
}

#[async_trait]
impl GetRawTransaction for Wallet {
    async fn get_raw_transaction(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction> {
        self.0.get_raw_transaction(txid).await.map_err(Into::into)
    }
}
