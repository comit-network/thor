use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey},
    signature,
    transaction::{build_shared_output_descriptor, SplitTransaction},
    Ptlc, PtlcPoint, TX_FEE,
};

use anyhow::{anyhow, Result};
use bitcoin::{
    util::bip143::SighashComponents, Address, OutPoint, Script, SigHash, Transaction, TxIn, TxOut,
};
use ecdsa_fun::{self, adaptor::EncryptedSignature, fun::Point, Signature};
use miniscript::Descriptor;
use serde::{Deserialize, Serialize};
use signature::{verify_encsig, verify_sig};
use std::collections::HashMap;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub(crate) struct RedeemTransaction {
    inner: Transaction,
    digest: SigHash,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
}

impl RedeemTransaction {
    pub fn new(tx_s: &SplitTransaction, ptlc: Ptlc, redeem_address: Address) -> Result<Self> {
        let (transaction, digest, input_descriptor) =
            spend_transaction(tx_s, ptlc, redeem_address, 0xFFFF_FFFF)?;

        Ok(Self {
            inner: transaction,
            digest,
            input_descriptor,
        })
    }

    pub fn sign(&self, x_self: &OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    pub fn encsign(&self, x_self: &OwnershipKeyPair, point: PtlcPoint) -> EncryptedSignature {
        x_self.encsign(point.into(), self.digest)
    }

    pub fn add_signatures(
        &self,
        (X_0, sig_0): (OwnershipPublicKey, Signature),
        (X_1, sig_1): (OwnershipPublicKey, Signature),
    ) -> Result<Transaction> {
        let satisfier = {
            let mut satisfier = HashMap::with_capacity(2);

            let X_0 = ::bitcoin::PublicKey {
                compressed: true,
                key: X_0.into(),
            };
            let X_1 = ::bitcoin::PublicKey {
                compressed: true,
                key: X_1.into(),
            };

            // The order in which these are inserted doesn't matter
            satisfier.insert(X_0, (sig_0.into(), ::bitcoin::SigHashType::All));
            satisfier.insert(X_1, (sig_1.into(), ::bitcoin::SigHashType::All));

            satisfier
        };

        let mut transaction = self.inner.clone();

        self.input_descriptor
            .satisfy(&mut transaction.input[0], satisfier)?;

        Ok(transaction)
    }

    pub fn verify_encsig(
        &self,
        verification_key: OwnershipPublicKey,
        encryption_key: Point,
        encsig: &EncryptedSignature,
    ) -> Result<()> {
        verify_encsig(verification_key, encryption_key, &self.digest, encsig)?;

        Ok(())
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub(crate) struct RefundTransaction {
    inner: Transaction,
    digest: SigHash,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
}

impl RefundTransaction {
    pub fn new(tx_s: &SplitTransaction, ptlc: Ptlc, refund_address: Address) -> Result<Self> {
        let (transaction, digest, input_descriptor) =
            spend_transaction(tx_s, ptlc.clone(), refund_address, ptlc.refund_time_lock)?;

        Ok(Self {
            inner: transaction,
            digest,
            input_descriptor,
        })
    }

    pub fn sign(&self, x_self: &OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    pub fn verify_sig(
        &self,
        verification_key: OwnershipPublicKey,
        signature: &Signature,
    ) -> Result<()> {
        verify_sig(verification_key, &self.digest, signature)?;

        Ok(())
    }

    pub fn add_signatures(
        &mut self,
        (X_0, sig_0): (OwnershipPublicKey, Signature),
        (X_1, sig_1): (OwnershipPublicKey, Signature),
    ) -> Result<()> {
        let satisfier = {
            let mut satisfier = HashMap::with_capacity(2);

            let X_0 = ::bitcoin::PublicKey {
                compressed: true,
                key: X_0.into(),
            };
            let X_1 = ::bitcoin::PublicKey {
                compressed: true,
                key: X_1.into(),
            };

            // The order in which these are inserted doesn't matter
            satisfier.insert(X_0, (sig_0.into(), ::bitcoin::SigHashType::All));
            satisfier.insert(X_1, (sig_1.into(), ::bitcoin::SigHashType::All));

            satisfier
        };

        let mut transaction = self.inner.clone();

        self.input_descriptor
            .satisfy(&mut transaction.input[0], satisfier)?;

        Ok(())
    }
}

pub(crate) fn spend_transaction(
    tx_s: &SplitTransaction,
    ptlc: Ptlc,
    refund_address: Address,
    input_sequence: u32,
) -> Result<(Transaction, SigHash, Descriptor<bitcoin::PublicKey>)> {
    let mut Xs = [ptlc.X_funder, ptlc.X_redeemer];
    Xs.sort_by(|a, b| a.partial_cmp(b).expect("comparison is possible"));
    let ptlc_output_descriptor = build_shared_output_descriptor(Xs[0].clone(), Xs[1].clone());

    let vout = tx_s
        .inner
        .output
        .iter()
        .position(|output| output.script_pubkey == ptlc_output_descriptor.script_pubkey())
        .ok_or_else(|| anyhow!("tx_s does not contain PTLC output"))?;

    #[allow(clippy::cast_possible_truncation)]
    let input = TxIn {
        previous_output: OutPoint::new(tx_s.txid(), vout as u32),
        script_sig: Script::new(),
        sequence: input_sequence,
        witness: Vec::new(),
    };

    let ptlc_output_value = tx_s.inner.output[vout].value;
    let output = TxOut {
        value: ptlc_output_value - TX_FEE,
        script_pubkey: refund_address.script_pubkey(),
    };

    let transaction = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![input.clone()],
        output: vec![output],
    };

    let digest = SighashComponents::new(&transaction).sighash_all(
        &input,
        &ptlc_output_descriptor.witness_script(),
        ptlc_output_value,
    );

    Ok((transaction, digest, ptlc_output_descriptor))
}

impl From<RefundTransaction> for Transaction {
    fn from(from: RefundTransaction) -> Self {
        from.inner
    }
}
