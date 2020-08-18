#![allow(non_snake_case)]

use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount};
use bitcoin_harness::{self, bitcoind_rpc::PsbtBase64, Bitcoind};
use reqwest::Url;
use thor::create::{Alice0, Bob0, BuildFundingPSBT, SignFundingPSBT};

pub struct Wallet(bitcoin_harness::Wallet);

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

#[tokio::test]
async fn e2e_channel_creation() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let alice_wallet = Wallet::new("alice", bitcoind.node_url.clone())
        .await
        .unwrap();
    let bob_wallet = Wallet::new("bob", bitcoind.node_url.clone()).await.unwrap();

    {
        // TODO: Could pass in the wallet and generate the address inside?
        let address = alice_wallet.0.new_address().await.unwrap();
        bitcoind
            .mint(address, Amount::from_btc(3.0).unwrap())
            .await
            .unwrap();
    }

    {
        let address = bob_wallet.0.new_address().await.unwrap();
        bitcoind
            .mint(address, Amount::from_btc(3.0).unwrap())
            .await
            .unwrap()
    };

    let time_lock = 1;
    let (channel_balance_alice, channel_balance_bob) = { (Amount::ONE_BTC, Amount::ONE_BTC) };

    let alice0 = Alice0::new(channel_balance_alice, time_lock);
    let bob0 = Bob0::new(channel_balance_bob, time_lock);

    let message0_alice = alice0.next_message();
    let message0_bob = bob0.next_message();

    let alice1 = alice0.receive(message0_bob, &alice_wallet).await.unwrap();
    let bob1 = bob0.receive(message0_alice, &bob_wallet).await.unwrap();

    let message1_alice = alice1.next_message();
    let message1_bob = bob1.next_message();

    let alice2 = alice1.receive(message1_bob).unwrap();
    let bob2 = bob1.receive(message1_alice).unwrap();

    let message2_alice = alice2.next_message();
    let message2_bob = bob2.next_message();

    let alice3 = alice2.receive(message2_bob).unwrap();
    let bob3 = bob2.receive(message2_alice).unwrap();

    let message3_alice = alice3.next_message();
    let message3_bob = bob3.next_message();

    let alice4 = alice3.receive(message3_bob).unwrap();
    let bob4 = bob3.receive(message3_alice).unwrap();

    let message4_alice = alice4.next_message();
    let message4_bob = bob4.next_message();

    let alice5 = alice4.receive(message4_bob).unwrap();
    let bob5 = bob4.receive(message4_alice).unwrap();

    let message5_alice = alice5.next_message(&alice_wallet).await.unwrap();
    let message5_bob = bob5.next_message(&bob_wallet).await.unwrap();

    let alice6 = alice5.receive(message5_bob, &alice_wallet).await.unwrap();
    let bob6 = bob5.receive(message5_alice, &bob_wallet).await.unwrap();

    assert_eq!(alice6.signed_TX_f, bob6.signed_TX_f);

    alice_wallet
        .0
        .send_raw_transaction(alice6.signed_TX_f.clone())
        .await
        .unwrap();
}
