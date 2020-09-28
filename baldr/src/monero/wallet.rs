use crate::monero::{
    Amount, CheckTransfer, ImportOutput, PrivateViewKey, PublicKey, PublicViewKey, Transfer,
    TransferProof, TxHash,
};
use anyhow::{bail, Result};
use async_trait::async_trait;
use monero::{Address, Network, PrivateKey};
use monero_harness::Monero;
use std::str::FromStr;

#[derive(Debug)]
pub struct AliceWallet<'c>(pub &'c Monero<'c>);

#[async_trait]
impl Transfer for AliceWallet<'_> {
    async fn transfer(
        &self,
        public_spend_key: PublicKey,
        public_view_key: PublicViewKey,
        amount: Amount,
    ) -> Result<TransferProof> {
        let destination_address =
            Address::standard(Network::Mainnet, public_spend_key, public_view_key.into());

        let res = self
            .0
            .transfer_from_alice(amount.0, &destination_address.to_string())
            .await?;

        let tx_hash = TxHash(res.tx_hash);
        let tx_key = PrivateKey::from_str(&res.tx_key)?;

        Ok(TransferProof { tx_hash, tx_key })
    }
}

#[derive(Debug)]
pub struct BobWallet<'c>(pub &'c Monero<'c>);

#[async_trait]
impl CheckTransfer for BobWallet<'_> {
    async fn check_transfer(
        &self,
        public_spend_key: PublicKey,
        public_view_key: PublicViewKey,
        transfer_proof: TransferProof,
        amount: Amount,
    ) -> Result<()> {
        let address = Address::standard(Network::Mainnet, public_spend_key, public_view_key.into());

        let cli = self.0.wallet_rpc_client();

        let res = cli
            .check_tx_key(
                &String::from(transfer_proof.tx_hash),
                &transfer_proof.tx_key.to_string(),
                &address.to_string(),
            )
            .await?;

        if res.received != u64::from(amount) {
            bail!(
                "tx_lock doesn't pay enough: expected {:?}, got {:?}",
                res.received,
                amount
            )
        }

        Ok(())
    }
}

#[async_trait]
impl ImportOutput for BobWallet<'_> {
    async fn import_output(
        &self,
        private_spend_key: PrivateKey,
        private_view_key: PrivateViewKey,
    ) -> Result<()> {
        let public_spend_key = PublicKey::from_private_key(&private_spend_key);
        let public_view_key = PublicKey::from_private_key(&private_view_key.into());

        let address = Address::standard(Network::Mainnet, public_spend_key, public_view_key);

        let _ = self
            .0
            .wallet_rpc_client()
            .generate_from_keys(
                &address.to_string(),
                &private_spend_key.to_string(),
                &PrivateKey::from(private_view_key).to_string(),
            )
            .await?;

        Ok(())
    }
}

#[async_trait]
impl ImportOutput for AliceWallet<'_> {
    async fn import_output(
        &self,
        private_spend_key: PrivateKey,
        private_view_key: PrivateViewKey,
    ) -> Result<()> {
        let public_spend_key = PublicKey::from_private_key(&private_spend_key);
        let public_view_key = PublicKey::from_private_key(&private_view_key.into());

        let address = Address::standard(Network::Mainnet, public_spend_key, public_view_key);

        let _ = self
            .0
            .wallet_rpc_client()
            .generate_from_keys(
                &address.to_string(),
                &private_spend_key.to_string(),
                &PrivateKey::from(private_view_key).to_string(),
            )
            .await?;

        Ok(())
    }
}
