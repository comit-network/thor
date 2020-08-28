use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount};
use bitcoin_harness::{bitcoind_rpc::PsbtBase64, Bitcoind};
use reqwest::Url;
use thor::{BroadcastSignedTransaction, BuildFundingPSBT, NewAddress, SignFundingPSBT};

pub struct Wallet(pub bitcoin_harness::Wallet);

impl Wallet {
    async fn new(name: &str, url: Url) -> anyhow::Result<Self> {
        let wallet = bitcoin_harness::Wallet::new(name, url).await?;

        Ok(Self(wallet))
    }
}

/// Create two bitcoind wallets on the node passed as an argument and fund them
/// with the amount that they will contribute to the channel, plus a buffer to
/// account for transaction fees.
pub async fn make_wallets(
    bitcoind: &Bitcoind<'_>,
    fund_amount_alice: Amount,
    fund_amount_bob: Amount,
) -> anyhow::Result<(Wallet, Wallet)> {
    let alice = Wallet::new("alice", bitcoind.node_url.clone()).await?;
    let bob = Wallet::new("bob", bitcoind.node_url.clone()).await?;

    let buffer = Amount::from_btc(1.0).unwrap();

    for (wallet, amount) in vec![(&alice, fund_amount_alice), (&bob, fund_amount_bob)].iter() {
        let address = wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, *amount + buffer).await.unwrap();
    }

    Ok((alice, bob))
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

        // TODO: Instead of guessing how long it will take for the transaction to be
        // mined we should ask bitcoind for the number of confirmations on `txid`

        // give time for transaction to be mined
        tokio::time::delay_for(std::time::Duration::from_millis(1100)).await;

        Ok(())
    }
}

#[async_trait::async_trait]
impl NewAddress for Wallet {
    async fn new_address(&self) -> anyhow::Result<Address> {
        self.0.new_address().await.map_err(Into::into)
    }
}
