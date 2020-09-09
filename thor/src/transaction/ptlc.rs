use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey},
    signature,
    transaction::{build_shared_output_descriptor, SplitTransaction},
    Ptlc, PtlcPoint, PtlcSecret, TX_FEE,
};

use anyhow::{bail, Context};
use arrayvec::ArrayVec;
use bitcoin::{
    util::bip143::SighashComponents, Address, OutPoint, Script, SigHash, Transaction, TxIn, TxOut,
    Txid,
};
use ecdsa_fun::{
    self,
    adaptor::{Adaptor, EncryptedSignature},
    fun::Point,
    nonce::Deterministic,
    Signature,
};
use miniscript::Descriptor;
use sha2::Sha256;
use signature::{verify_encsig, verify_sig};
use std::collections::HashMap;

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
pub(crate) struct RedeemTransaction {
    inner: Transaction,
    digest: SigHash,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
}

impl RedeemTransaction {
    pub fn new(
        TX_s: &SplitTransaction,
        ptlc: Ptlc,
        redeem_address: Address,
    ) -> anyhow::Result<Self> {
        let (transaction, digest, input_descriptor) =
            spend_transaction(TX_s, ptlc, redeem_address, 0xFFFF_FFFF)?;

        Ok(Self {
            inner: transaction,
            digest,
            input_descriptor,
        })
    }

    pub fn sign_once(&self, x_self: &OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    pub fn encsign_once(&self, x_self: &OwnershipKeyPair, point: PtlcPoint) -> EncryptedSignature {
        x_self.encsign(point.into(), self.digest)
    }

    pub fn add_signatures(
        &self,
        (X_0, sig_0): (OwnershipPublicKey, Signature),
        (X_1, sig_1): (OwnershipPublicKey, Signature),
    ) -> anyhow::Result<Self> {
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

        let mut transaction = self.clone();
        self.input_descriptor
            .satisfy(&mut transaction.inner.input[0], satisfier)?;

        Ok(transaction)
    }

    pub fn verify_encsig(
        &self,
        verification_key: OwnershipPublicKey,
        encryption_key: Point,
        encsig: &EncryptedSignature,
    ) -> anyhow::Result<()> {
        verify_encsig(verification_key, encryption_key, &self.digest, encsig)?;

        Ok(())
    }

    pub fn txid(&self) -> Txid {
        self.inner.txid()
    }
}

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Clone, Debug)]
pub(crate) struct RefundTransaction {
    inner: Transaction,
    digest: SigHash,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
}

impl RefundTransaction {
    pub fn new(
        TX_s: &SplitTransaction,
        ptlc: Ptlc,
        refund_address: Address,
    ) -> anyhow::Result<Self> {
        let (transaction, digest, input_descriptor) =
            spend_transaction(TX_s, ptlc.clone(), refund_address, ptlc.refund_time_lock)?;

        Ok(Self {
            inner: transaction,
            digest,
            input_descriptor,
        })
    }

    pub fn sign_once(&self, x_self: &OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    pub fn verify_sig(
        &self,
        verification_key: OwnershipPublicKey,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        verify_sig(verification_key, &self.digest, signature)?;

        Ok(())
    }

    pub fn add_signatures(
        &mut self,
        (X_0, sig_0): (OwnershipPublicKey, Signature),
        (X_1, sig_1): (OwnershipPublicKey, Signature),
    ) -> anyhow::Result<()> {
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

        self.input_descriptor
            .satisfy(&mut self.inner.input[0], satisfier)?;

        Ok(())
    }
}

pub(crate) fn spend_transaction(
    TX_s: &SplitTransaction,
    ptlc: Ptlc,
    refund_address: Address,
    lock_time: u32,
) -> anyhow::Result<(Transaction, SigHash, Descriptor<bitcoin::PublicKey>)> {
    let mut Xs = [ptlc.X_funder, ptlc.X_redeemer];
    Xs.sort_by(|a, b| a.partial_cmp(b).expect("comparison is possible"));
    let [X_0, X_1] = Xs;
    let ptlc_output_descriptor = build_shared_output_descriptor(X_0, X_1);

    let vout = TX_s
        .inner
        .output
        .iter()
        .position(|output| output.script_pubkey == ptlc_output_descriptor.script_pubkey())
        .ok_or_else(|| anyhow::anyhow!("TX_s does not contain PTLC output"))?;

    #[allow(clippy::cast_possible_truncation)]
    let input = TxIn {
        previous_output: OutPoint::new(TX_s.txid(), vout as u32),
        script_sig: Script::new(),
        sequence: 0xFFFF_FFFF,
        witness: Vec::new(),
    };

    let ptlc_output_value = TX_s.inner.output[vout].value;
    let output = TxOut {
        value: ptlc_output_value - TX_FEE,
        script_pubkey: refund_address.script_pubkey(),
    };

    let transaction = Transaction {
        version: 2,
        lock_time,
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

impl From<RedeemTransaction> for Transaction {
    fn from(from: RedeemTransaction) -> Self {
        from.inner
    }
}

impl From<RefundTransaction> for Transaction {
    fn from(from: RefundTransaction) -> Self {
        from.inner
    }
}

pub(crate) fn extract_signature_by_key(
    candidate_transaction: Transaction,
    TX_ptlc_redeem: RedeemTransaction,
    X_self: OwnershipPublicKey,
) -> anyhow::Result<Signature> {
    let input = match candidate_transaction.input.as_slice() {
        [input] => input,
        [] => bail!(NoInputs),
        [inputs @ ..] => bail!(TooManyInputs(inputs.len())),
    };

    let sigs = match input
        .witness
        .iter()
        .map(|vec| vec.as_slice())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [sig_1 @ [..], sig_2 @ [..], _script @ [..]] => [sig_1, sig_2]
            .iter()
            .map(|sig| {
                bitcoin::secp256k1::Signature::from_der(&sig[..sig.len() - 1]).map(Signature::from)
            })
            .collect::<Result<ArrayVec<[_; 2]>, _>>()
            .context("unknown witness layout")?
            .into_inner()
            .expect("inner array is full to capacity"),
        [] => bail!(EmptyWitnessStack),
        [witnesses @ ..] => bail!(NotThreeWitnesses(witnesses.len())),
    };

    let sig = sigs
        .iter()
        .find(|sig| signature::verify_sig(X_self.clone(), &TX_ptlc_redeem.digest, &sig).is_ok())
        .context("neither signature on witness stack verifies against X_self")?;

    Ok(sig.clone())
}

#[derive(thiserror::Error, Debug)]
#[error("transaction does not spend anything")]
pub struct NoInputs;

#[derive(thiserror::Error, Debug)]
#[error("transaction has {0} inputs, expected 1")]
pub struct TooManyInputs(usize);

#[derive(thiserror::Error, Debug)]
#[error("empty witness stack")]
pub struct EmptyWitnessStack;

#[derive(thiserror::Error, Debug)]
#[error("input has {0} witnesses, expected 3")]
pub struct NotThreeWitnesses(usize);

pub fn recover_secret(
    ptlc_point: PtlcPoint,
    sig_TX_ptlc_redeem_funder: Signature,
    encsig_TX_ptlc_redeem_funder: EncryptedSignature,
) -> anyhow::Result<PtlcSecret> {
    let adaptor = Adaptor::<Sha256, Deterministic<Sha256>>::default();

    let secret = adaptor
        .recover_decryption_key(
            &ptlc_point.into(),
            &sig_TX_ptlc_redeem_funder,
            &encsig_TX_ptlc_redeem_funder,
        )
        .map(PtlcSecret::from)
        .ok_or_else(|| anyhow::anyhow!("PTLC secret recovery failure"))?;

    Ok(secret)
}
