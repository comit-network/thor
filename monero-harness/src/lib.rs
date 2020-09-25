#![warn(
    unused_extern_crates,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::fallible_impl_from,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::dbg_macro
)]
#![forbid(unsafe_code)]

//! # monero-harness
//!
//! A simple lib to start a monero container (incl. monerod and
//! monero-wallet-rpc). Provides initialisation methods to generate blocks,
//! create and fund accounts, and start a continuous mining task mining blocks
//! every BLOCK_TIME_SECS seconds.
//!
//! Also provides standalone JSON RPC clients for monerod and monero-wallet-rpc.

pub mod image;
pub mod rpc;

use anyhow::Result;
use rand::Rng;
use serde::Deserialize;
use std::time::Duration;
use testcontainers::{clients::Cli, core::Port, Container, Docker};
use tokio::time;

use crate::{
    image::{MONEROD_RPC_PORT, WALLET_RPC_PORT},
    rpc::{
        monerod,
        wallet::{self, GetAddress, Transfer},
    },
};

/// How often we mine a block.
const BLOCK_TIME_SECS: u64 = 1;

/// Poll interval when checking if the wallet has synced with monerod.
const WAIT_WALLET_SYNC_MILLIS: u64 = 1000;

/// Wallet sub-account indecies.
const ACCOUNT_INDEX_PRIMARY: u32 = 0;
const ACCOUNT_INDEX_ALICE: u32 = 1;
const ACCOUNT_INDEX_BOB: u32 = 2;

#[derive(Debug)]
pub struct Monero<'c> {
    pub docker: Container<'c, Cli, image::Monero>,
    pub monerod_rpc_port: u16,
    pub wallet_rpc_port: u16,
}

impl<'c> Monero<'c> {
    /// Starts a new regtest monero container.
    pub fn new(cli: &'c Cli) -> Self {
        let mut rng = rand::thread_rng();
        let monerod_rpc_port: u16 = rng.gen_range(1024, u16::MAX);
        let wallet_rpc_port: u16 = rng.gen_range(1024, u16::MAX);

        let image = image::Monero::default()
            .with_mapped_port(Port {
                local: monerod_rpc_port,
                internal: MONEROD_RPC_PORT,
            })
            .with_mapped_port(Port {
                local: wallet_rpc_port,
                internal: WALLET_RPC_PORT,
            });

        println!("running image ...");
        let docker = cli.run(image);
        println!("image ran");

        Self {
            docker,
            monerod_rpc_port,
            wallet_rpc_port,
        }
    }

    pub fn wallet_rpc_client(&self) -> wallet::Client {
        wallet::Client::localhost(self.wallet_rpc_port)
    }

    pub fn monerod_rpc_client(&self) -> monerod::Client {
        monerod::Client::localhost(self.monerod_rpc_port)
    }

    /// Initialise by creating a wallet, generating some `blocks`, and starting
    /// a miner thread that mines to the primary account. Also create two
    /// sub-accounts, one for Alice and one for Bob. If alice/bob_funding is
    /// some, the value needs to be > 0.
    pub async fn init(&self, alice_funding: u64, bob_funding: u64) -> Result<()> {
        let wallet = self.wallet_rpc_client();
        let monerod = self.monerod_rpc_client();

        wallet.create_wallet("miner_wallet").await?;

        let alice = wallet.create_account("alice").await?;
        let bob = wallet.create_account("bob").await?;

        let miner = self.get_address_primary().await?.address;

        let res = monerod.generate_blocks(70, &miner).await?;
        self.wait_for_wallet_block_height(res.height).await?;

        if alice_funding > 0 {
            self.fund_account(&alice.address, &miner, alice_funding)
                .await?;
            let balance = self.get_balance_alice().await?;
            debug_assert!(balance == alice_funding);
        }

        if bob_funding > 0 {
            self.fund_account(&bob.address, &miner, bob_funding).await?;
            let balance = self.get_balance_bob().await?;
            debug_assert!(balance == bob_funding);
        }

        let _ = tokio::spawn(mine(monerod.clone(), miner));

        Ok(())
    }

    /// Just create a wallet and start mining (you probably want `init()`).
    pub async fn init_just_miner(&self, blocks: u32) -> Result<()> {
        let wallet = self.wallet_rpc_client();
        let monerod = self.monerod_rpc_client();

        wallet.create_wallet("miner_wallet").await?;
        let miner = self.get_address_primary().await?.address;

        let _ = monerod.generate_blocks(blocks, &miner).await?;

        let _ = tokio::spawn(mine(monerod.clone(), miner));

        Ok(())
    }

    async fn fund_account(&self, address: &str, miner: &str, funding: u64) -> Result<()> {
        let monerod = self.monerod_rpc_client();

        self.transfer_from_primary(funding, address).await?;
        let res = monerod.generate_blocks(10, miner).await?;
        self.wait_for_wallet_block_height(res.height).await?;

        Ok(())
    }

    // It takes a little while for the wallet to sync with monerod.
    async fn wait_for_wallet_block_height(&self, height: u32) -> Result<()> {
        let wallet = self.wallet_rpc_client();
        while wallet.block_height().await?.height < height {
            time::delay_for(Duration::from_millis(WAIT_WALLET_SYNC_MILLIS)).await;
        }
        Ok(())
    }

    /// Get addresses for the primary account.
    pub async fn get_address_primary(&self) -> Result<GetAddress> {
        let wallet = self.wallet_rpc_client();
        wallet.get_address(ACCOUNT_INDEX_PRIMARY).await
    }

    /// Get addresses for the Alice's account.
    pub async fn get_address_alice(&self) -> Result<GetAddress> {
        let wallet = self.wallet_rpc_client();
        wallet.get_address(ACCOUNT_INDEX_ALICE).await
    }

    /// Get addresses for the Bob's account.
    pub async fn get_address_bob(&self) -> Result<GetAddress> {
        let wallet = self.wallet_rpc_client();
        wallet.get_address(ACCOUNT_INDEX_BOB).await
    }

    /// Gets the balance of the wallet primary account.
    pub async fn get_balance_primary(&self) -> Result<u64> {
        let wallet = self.wallet_rpc_client();
        wallet.get_balance(ACCOUNT_INDEX_PRIMARY).await
    }

    /// Gets the balance of Alice's account.
    pub async fn get_balance_alice(&self) -> Result<u64> {
        let wallet = self.wallet_rpc_client();
        wallet.get_balance(ACCOUNT_INDEX_ALICE).await
    }

    /// Gets the balance of Bob's account.
    pub async fn get_balance_bob(&self) -> Result<u64> {
        let wallet = self.wallet_rpc_client();
        wallet.get_balance(ACCOUNT_INDEX_BOB).await
    }

    /// Transfers moneroj from the primary account.
    pub async fn transfer_from_primary(&self, amount: u64, address: &str) -> Result<Transfer> {
        let wallet = self.wallet_rpc_client();
        wallet
            .transfer(ACCOUNT_INDEX_PRIMARY, amount, address)
            .await
    }

    /// Transfers moneroj from Alice's account.
    pub async fn transfer_from_alice(&self, amount: u64, address: &str) -> Result<Transfer> {
        let wallet = self.wallet_rpc_client();
        wallet.transfer(ACCOUNT_INDEX_ALICE, amount, address).await
    }

    /// Transfers moneroj from Bob's account.
    pub async fn transfer_from_bob(&self, amount: u64, address: &str) -> Result<Transfer> {
        let wallet = self.wallet_rpc_client();
        wallet.transfer(ACCOUNT_INDEX_BOB, amount, address).await
    }
}

/// Mine a block ever BLOCK_TIME_SECS seconds.
async fn mine(monerod: monerod::Client, reward_address: String) -> Result<()> {
    loop {
        time::delay_for(Duration::from_secs(BLOCK_TIME_SECS)).await;
        monerod.generate_blocks(1, &reward_address).await?;
    }
}

// We should be able to use monero-rs for this but it does not include all
// the fields.
#[derive(Clone, Debug, Deserialize)]
pub struct BlockHeader {
    pub block_size: u32,
    pub depth: u32,
    pub difficulty: u32,
    pub hash: String,
    pub height: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub nonce: u32,
    pub num_txes: u32,
    pub orphan_status: bool,
    pub prev_hash: String,
    pub reward: u64,
    pub timestamp: u32,
}
