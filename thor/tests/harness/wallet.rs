use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{consensus, util::psbt::PartiallySignedTransaction, Address, Amount};
use bitcoin_harness::{bitcoind_rpc::PsbtBase64, Bitcoind};
use reqwest::Url;
use thor::{BroadcastSignedTransaction, BuildFundingPsbt, NewAddress, SignFundingPsbt};

pub struct Wallet(pub bitcoin_harness::Wallet);

impl Wallet {
    async fn new(name: &str, url: Url) -> Result<Self> {
        let wallet = bitcoin_harness::Wallet::new(name, url).await?;

        Ok(Self(wallet))
    }

    pub async fn balance(&self) -> Result<Amount> {
        let b = self.0.balance().await?;
        Ok(b)
    }
}

/// Create two bitcoind wallets on the `bitcoind` node and fund them with the
/// amount that they will contribute to the channel, plus a buffer to account
/// for transaction fees.
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

    let buffer = Amount::from_btc(1.0)?;
    let address = wallet.0.new_address().await.unwrap();
    bitcoind.mint(address, fund_amount + buffer).await.unwrap();

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
        let psbt = consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}

#[async_trait]
impl SignFundingPsbt for Wallet {
    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction> {
        let psbt = consensus::serialize(&psbt);
        let as_base64 = base64::encode(psbt);

        let psbt = self.0.wallet_process_psbt(PsbtBase64(as_base64)).await?;
        let PsbtBase64(signed_psbt) = PsbtBase64::from(psbt);

        let as_hex = base64::decode(signed_psbt)?;
        let psbt = consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}

#[async_trait]
impl BroadcastSignedTransaction for Wallet {
    async fn broadcast_signed_transaction(&self, transaction: bitcoin::Transaction) -> Result<()> {
        let _txid = self.0.send_raw_transaction(transaction).await?;

        // TODO: Instead of guessing how long it will take for the transaction to be
        // mined we should ask bitcoind for the number of confirmations on `txid`

        // Give time for transaction to be mined.
        tokio::time::delay_for(std::time::Duration::from_millis(1100)).await;

        Ok(())
    }
}

#[async_trait]
impl NewAddress for Wallet {
    async fn new_address(&self) -> Result<Address> {
        self.0.new_address().await.map_err(Into::into)
    }
}
