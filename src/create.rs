use std::{collections::HashMap, marker::PhantomData};

use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    signature::{verify_encsig, verify_sig},
    transaction::{
        CommitTransaction, FundingTransaction, PartialFundingTransaction, SplitTransaction,
    },
    ChannelState,
};
use anyhow::{bail, Context};
use bitcoin::{
    hashes::{core::convert::TryInto, hex::ToHex, Hash},
    secp256k1,
    secp256k1::{Message, Secp256k1},
    util::psbt::PartiallySignedTransaction,
    Address, Amount, Network, PublicKey, Script, SigHashType, Transaction, TxIn,
};
use bitcoin_harness::{bitcoincore_rpc, bitcoincore_rpc::RpcApi};
use ecdsa_fun::{adaptor::EncryptedSignature, fun::Scalar, nonce, Signature, ECDSA};
use rand::prelude::ThreadRng;
use sha2::Sha256;

pub struct Wallet {
    inner: bitcoin_harness::Wallet,
    funding_address: Address,
    funding_input_tx: Transaction,
}

impl Wallet {
    fn new(
        wallet: bitcoin_harness::Wallet,
        funding_address: Address,
        funding_input_tx: Transaction,
    ) -> Self {
        Self {
            inner: wallet,
            funding_address,
            funding_input_tx,
        }
    }

    fn create_partial_funded_transaction(
        &self,
        (X_a, txin_a): (OwnershipPublicKey, (TxIn, Amount)),
        (X_b, txin_b): (OwnershipPublicKey, (TxIn, Amount)),
    ) -> anyhow::Result<PartialFundingTransaction> {
        // bitcoincore-rpc client does not provide all endpoints to fully use psbts,
        // hence we do it manually
        PartialFundingTransaction::new((X_a, txin_a), (X_b, txin_b))
    }

    fn join_partial_transaction(
        &self,
        partial_tx_f_a: PartialFundingTransaction,
        partial_tx_f_b: PartialFundingTransaction,
    ) -> anyhow::Result<FundingTransaction> {
        let tx_f_a = partial_tx_f_a.as_transaction();
        let tx_f_b = partial_tx_f_b.as_transaction();

        let mut inputs = tx_f_a.input.clone();
        inputs.extend(tx_f_b.input);

        // TODO remove duplicated output
        let mut outputs = tx_f_a.output;
        outputs.extend(tx_f_b.output);

        Ok(FundingTransaction::new(
            Transaction {
                version: 2,
                lock_time: 0,
                input: inputs,
                output: outputs,
            },
            partial_tx_f_a.output_descriptor(),
        ))
    }

    fn sign(self, transaction: FundingTransaction) -> anyhow::Result<FundingTransaction> {
        let bitcoincore_json_rpc_client = bitcoincore_rpc::Client::from(self.inner);
        let private_key = bitcoincore_json_rpc_client.dump_private_key(&self.funding_address)?;
        let funding_address_info =
            bitcoincore_json_rpc_client.get_address_info(&self.funding_address)?;

        let digest = transaction.compute_digest(
            funding_address_info.pubkey.unwrap(),
            self.funding_input_tx.txid(),
        )?;

        // TODO use secpFun
        let secp = Secp256k1::new();
        let message_to_sign = Message::from_slice(&digest.into_inner()).unwrap();
        let signature = secp.sign(&message_to_sign, &private_key.key);

        // TODO put signature into transaction with miniscript
        let transaction = FundingTransaction::new(
            transaction.as_transaction(),
            transaction.output_descriptor(),
        );
        Ok(transaction)
    }
}

pub struct Message0_0 {
    X: OwnershipPublicKey,
    tid: (TxIn, Amount),
    time_lock: u32,
}

pub struct Message0_1 {
    X: OwnershipPublicKey,
    partial_TX_f: PartialFundingTransaction,
}

pub struct Message1 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

pub struct Message2 {
    sig_TX_s: Signature,
}

pub struct Message3 {
    encsig_TX_c: EncryptedSignature,
}

pub struct Message4 {
    TX_f_signed_once: FundingTransaction,
}

pub struct Alice0_0 {
    x_self: OwnershipKeyPair,
    tid_self: (TxIn, Amount),
    time_lock: u32,
    wallet: Wallet,
}

impl Alice0_0 {
    pub fn new(tid_self: (TxIn, Amount), time_lock: u32, wallet: Wallet) -> Self {
        let x_self = OwnershipKeyPair::new_random();

        Self {
            x_self,
            tid_self,
            time_lock,
            wallet,
        }
    }

    pub fn next_message(&self) -> Message0_0 {
        Message0_0 {
            X: self.x_self.public(),
            tid: self.tid_self.clone(),
            time_lock: self.time_lock,
        }
    }

    pub fn receive(
        self,
        Message0_0 {
            X: X_other,
            tid: tid_other,
            time_lock: time_lock_other,
        }: Message0_0,
    ) -> anyhow::Result<Alice0_1> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory
        check_timelocks(self.time_lock, time_lock_other)?;

        let partial_TX_f = self
            .wallet
            .create_partial_funded_transaction(
                (self.x_self.public(), self.tid_self.clone()),
                (X_other.clone(), tid_other.clone()),
            )
            .context("failed to build funding transaction")?;

        Ok(Alice0_1 {
            x_self: self.x_self,
            X_other,
            tid_self: self.tid_self,
            tid_other,
            time_lock: self.time_lock,
            partial_TX_f,
            wallet: self.wallet,
        })
    }
}

pub struct Bob0_0 {
    x_self: OwnershipKeyPair,
    tid_self: (TxIn, Amount),
    time_lock: u32,
    wallet: Wallet,
}

impl Bob0_0 {
    pub fn new(tid_self: (TxIn, Amount), time_lock: u32, wallet: Wallet) -> Self {
        let x_self = OwnershipKeyPair::new_random();
        Self {
            x_self,
            tid_self,
            time_lock,
            wallet,
        }
    }

    pub fn next_message(&self) -> Message0_0 {
        Message0_0 {
            X: self.x_self.public(),
            tid: self.tid_self.clone(),
            time_lock: self.time_lock,
        }
    }

    pub fn receive(
        self,
        Message0_0 {
            X: X_other,
            tid: tid_other,
            time_lock: time_lock_other,
        }: Message0_0,
    ) -> anyhow::Result<Bob0_1> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory
        check_timelocks(self.time_lock, time_lock_other)?;

        let partial_TX_f = self
            .wallet
            .create_partial_funded_transaction(
                (X_other.clone(), tid_other.clone()),
                (self.x_self.public(), self.tid_self.clone()),
            )
            .context("failed to build funding transaction")?;

        Ok(Bob0_1 {
            x_self: self.x_self,
            X_other,
            tid_self: self.tid_self,
            tid_other,
            time_lock: self.time_lock,
            partial_TX_f,
            wallet: self.wallet,
        })
    }
}
pub struct Alice0_1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    time_lock: u32,
    partial_TX_f: PartialFundingTransaction,
    wallet: Wallet,
}

impl Alice0_1 {
    pub fn next_message(&self) -> Message0_1 {
        Message0_1 {
            X: self.x_self.public(),
            partial_TX_f: self.partial_TX_f.clone(),
        }
    }

    pub fn receive(
        self,
        Message0_1 {
            X: X_other,
            partial_TX_f: partial_tx_f_other,
        }: Message0_1,
    ) -> anyhow::Result<Alice1> {
        let TX_f = self
            .wallet
            .join_partial_transaction(self.partial_TX_f, partial_tx_f_other)?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();
        Ok(Alice1 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            time_lock: self.time_lock,
            r_self: r,
            y_self: y,
            TX_f,
        })
    }
}

pub struct Bob0_1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    time_lock: u32,
    partial_TX_f: PartialFundingTransaction,
    wallet: Wallet,
}

impl Bob0_1 {
    pub fn next_message(&self) -> Message0_1 {
        Message0_1 {
            X: self.x_self.public(),
            partial_TX_f: self.partial_TX_f.clone(),
        }
    }

    pub fn receive(
        self,
        Message0_1 {
            X: X_other,
            partial_TX_f: partial_tx_f_other,
        }: Message0_1,
    ) -> anyhow::Result<Bob1> {
        let TX_f = self
            .wallet
            .join_partial_transaction(partial_tx_f_other, self.partial_TX_f)?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();
        Ok(Bob1 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            time_lock: self.time_lock,
            r_self: r,
            y_self: y,
            TX_f,
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("time_locks are not equal")]
pub struct IncompatibleTimeLocks;

fn check_timelocks(time_lock_self: u32, time_lock_other: u32) -> Result<(), IncompatibleTimeLocks> {
    if time_lock_self != time_lock_other {
        Err(IncompatibleTimeLocks)
    } else {
        Ok(())
    }
}

pub struct Alice1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl Alice1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
    ) -> anyhow::Result<Party2> {
        let TX_c = CommitTransaction::new(
            &self.TX_f,
            (
                self.x_self.public(),
                self.r_self.public(),
                self.y_self.public(),
            ),
            (self.X_other.clone(), R_other, Y_other.clone()),
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other);

        let TX_s = SplitTransaction::new(&TX_c, ChannelState {
            a: (self.tid_self.1, self.x_self.public()),
            b: (self.tid_other.1, self.X_other.clone()),
        })?;
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(Party2 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        })
    }
}

pub struct Bob1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl Bob1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
    ) -> anyhow::Result<Party2> {
        let TX_c = CommitTransaction::new(
            &self.TX_f,
            (self.X_other.clone(), R_other, Y_other.clone()),
            (
                self.x_self.public(),
                self.r_self.public(),
                self.y_self.public(),
            ),
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other);

        let TX_s = SplitTransaction::new(&TX_c, ChannelState {
            a: (self.tid_other.1, self.X_other.clone()),
            b: (self.tid_self.1, self.x_self.public()),
        })?;
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(Party2 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c,
            TX_s,
            sig_TX_s_self,
            encsig_TX_c_self,
        })
    }
}

pub struct Party2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
}

impl Party2 {
    pub fn next_message(&self) -> Message2 {
        Message2 {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message2 {
            sig_TX_s: sig_TX_s_other,
        }: Message2,
    ) -> anyhow::Result<Party3> {
        verify_sig(self.X_other.clone(), &self.TX_s, &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        Ok(Party3 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            sig_TX_s_self: self.sig_TX_s_self,
            sig_TX_s_other,
        })
    }
}

pub struct Party3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
    sig_TX_s_other: Signature,
}

impl Party3 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message3 {
            encsig_TX_c: encsig_TX_c_other,
        }: Message3,
    ) -> anyhow::Result<Party4> {
        verify_encsig(
            self.X_other.clone(),
            self.y_self.public(),
            &self.TX_c,
            &encsig_TX_c_other,
        )
        .context("failed to verify sig_TX_s sent by counterparty")?;

        Ok(Party4 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other,
            sig_TX_s_self: self.sig_TX_s_self,
            sig_TX_s_other: self.sig_TX_s_other,
        })
    }
}

pub struct Party4 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
    sig_TX_s_self: Signature,
    sig_TX_s_other: Signature,
}

impl Party4 {
    pub async fn next_message(&self, wallet: Wallet) -> anyhow::Result<Message4> {
        let TX_f_signed_once = wallet.sign(self.TX_f.clone())?;

        Ok(Message4 { TX_f_signed_once })
    }

    pub async fn receive(
        self,
        Message4 { TX_f_signed_once }: Message4,
        wallet: Wallet,
    ) -> anyhow::Result<Party5> {
        let signed_TX_f = wallet.sign(TX_f_signed_once)?;

        Ok(Party5 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            signed_TX_f,
            TX_c: self.TX_c,
            TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other: self.encsig_TX_c_other,
            sig_TX_s_self: self.sig_TX_s_self,
            sig_TX_s_other: self.sig_TX_s_other,
        })
    }
}

/// A party which has reached this state is now able to safely
/// broadcast the `FundingTransaction` in order to open the channel.
pub struct Party5 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    signed_TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
    sig_TX_s_self: Signature,
    sig_TX_s_other: Signature,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Transaction: ")]
    Transaction(#[from] crate::transaction::Error),
}

#[cfg(test)]
mod test {
    use bitcoin::{Address, OutPoint, Transaction};
    use bitcoin_harness::{bitcoincore_rpc, Bitcoind};
    use testcontainers::clients;

    use super::*;

    fn find_tx_output(transaction: Transaction, address: Address) -> anyhow::Result<TxIn> {
        let txid = transaction.txid();

        let vout = transaction
            .output
            .iter()
            .position(|txout| txout.script_pubkey.eq(&address.script_pubkey()))
            .ok_or_else(|| anyhow::anyhow!("Address not found in transaction"))?
            as u32;

        Ok(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: Default::default(),
            sequence: u32::MAX,
            witness: vec![],
        })
    }

    #[tokio::test]
    async fn channel_creation() -> anyhow::Result<()> {
        let tc_client = clients::Cli::default();
        let bitcoind = Bitcoind::new(&tc_client, "0.19.1")?;
        bitcoind.init(5).await?;

        let time_lock = 60 * 60;

        let alice0_0 = {
            let wallet = bitcoind.new_wallet("alice")?;
            let address = wallet.new_address()?;
            let transaction = bitcoind.mint(&address, Amount::ONE_BTC).await?;

            let input = find_tx_output(transaction.clone(), address.clone())?;
            let amount = Amount::from_sat(1_000);

            Alice0_0::new(
                (input, amount),
                time_lock,
                Wallet::new(wallet, address, transaction),
            )
        };

        let bob0_0 = {
            let wallet = bitcoind.new_wallet("bob")?;
            let address = wallet.new_address()?;
            let transaction = bitcoind.mint(&address, Amount::ONE_BTC).await?;

            let input = find_tx_output(transaction.clone(), address.clone())?;
            let amount = Amount::from_sat(1_000);

            Bob0_0::new(
                (input, amount),
                time_lock,
                Wallet::new(wallet, address, transaction),
            )
        };

        let message0_alice = alice0_0.next_message();
        let message0_bob = bob0_0.next_message();

        let alice0_1 = alice0_0.receive(message0_bob)?;
        let bob_0_1 = bob0_0.receive(message0_alice)?;

        let message0_alice = alice0_1.next_message();
        let message0_bob = bob_0_1.next_message();

        let alice1 = alice0_1.receive(message0_bob)?;
        let bob1 = bob_0_1.receive(message0_alice)?;

        let message1_alice = alice1.next_message();
        let message1_bob = bob1.next_message();

        let alice2 = alice1.receive(message1_bob)?;
        let bob2 = bob1.receive(message1_alice)?;

        let message2_alice = alice2.next_message();
        let message2_bob = bob2.next_message();

        let alice3 = alice2.receive(message2_bob)?;
        let bob3 = bob2.receive(message2_alice)?;

        let message3_alice = alice3.next_message();
        let message3_bob = bob3.next_message();

        let alice4 = alice3.receive(message3_bob)?;
        let bob4 = bob3.receive(message3_alice)?;

        Ok(())
    }
}
