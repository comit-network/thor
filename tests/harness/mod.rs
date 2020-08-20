pub mod close;

use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount};
use bitcoin_harness::bitcoind_rpc::PsbtBase64;
use reqwest::Url;
use thor::{
    create::{BuildFundingPSBT, SignFundingPSBT},
    BroadcastSignedTransaction,
};

pub struct Wallet(pub bitcoin_harness::Wallet);

impl Wallet {
    pub async fn new(name: &str, url: Url) -> anyhow::Result<Self> {
        let wallet = bitcoin_harness::Wallet::new(name, url).await?;

        Ok(Self(wallet))
    }
}

#[async_trait::async_trait]
impl BuildFundingPSBT for Wallet {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> anyhow::Result<PartiallySignedTransaction> {
        let psbt = self.0.fund_psbt(output_address, output_amount).await?;
        let as_hex = base64::decode(psbt)?;

        let psbt = bitcoin::consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}

#[async_trait::async_trait]
impl SignFundingPSBT for Wallet {
    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> anyhow::Result<PartiallySignedTransaction> {
        let psbt = bitcoin::consensus::serialize(&psbt);
        let as_base64 = base64::encode(psbt);

        let psbt = self.0.wallet_process_psbt(PsbtBase64(as_base64)).await?;
        let PsbtBase64(signed_psbt) = PsbtBase64::from(psbt);

        let as_hex = base64::decode(signed_psbt)?;
        let psbt = bitcoin::consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}

#[async_trait::async_trait]
impl BroadcastSignedTransaction for Wallet {
    async fn broadcast_signed_transaction(
        &self,
        transaction: bitcoin::Transaction,
    ) -> anyhow::Result<()> {
        let _txid = self.0.send_raw_transaction(transaction).await?;

        Ok(())
    }
}
