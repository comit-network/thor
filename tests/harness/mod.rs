pub mod create;

use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount};
use bitcoin_harness::bitcoind_rpc::PsbtBase64;
use reqwest::Url;
use thor::{
    create::{BuildFundingPSBT, SignFundingPSBT},
    update::{self, ChannelUpdate},
};

pub struct UpdateActors {
    pub alice: update::Party0,
    pub bob: update::Party0,
}

pub fn make_update_actors(alice: thor::create::Party6, bob: thor::create::Party6) -> UpdateActors {
    let alice = update::Party0::new(alice);
    let bob = update::Party0::new(bob);

    UpdateActors { alice, bob }
}

pub struct Updated {
    pub alice: update::Party0,
    pub bob: update::Party0,
}

pub fn run_update_protocol(
    alice0: update::Party0,
    bob0: update::Party0,
    channel_update: ChannelUpdate,
    time_lock: u32,
) -> Updated {
    let (alice1, message0) = alice0
        .propose_channel_update(channel_update, time_lock)
        .unwrap();

    let (bob1, message1) = bob0.receive_channel_update(message0).unwrap();

    let alice2 = alice1.receive(message1).unwrap();

    let message2_alice = alice2.next_message();
    let message2_bob = bob1.next_message();

    let alice3 = alice2.receive(message2_bob).unwrap();
    let bob2 = bob1.receive(message2_alice).unwrap();

    let message3_alice = alice3.next_message();
    let message3_bob = bob2.next_message();

    let alice4 = alice3.receive(message3_bob).unwrap();
    let bob3 = bob2.receive(message3_alice).unwrap();

    let message4_alice = alice4.next_message();
    let message4_bob = bob3.next_message();

    let alice5 = alice4.receive(message4_bob).unwrap();
    let bob4 = bob3.receive(message4_alice).unwrap();

    Updated {
        alice: alice5,
        bob: bob4,
    }
}

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
