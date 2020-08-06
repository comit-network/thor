use crate::{
    keys::{PublicKey, PublishingPublicKey, RevocationPublicKey},
    ChannelState,
};
use anyhow::Context;
use bitcoin::{
    secp256k1, util::bip143::SighashComponents, Amount, OutPoint, Script, SigHash, Transaction,
    TxIn, TxOut,
};
use std::str::FromStr;

#[derive(Clone)]
pub struct FundingTransaction(Transaction);

impl FundingTransaction {
    // A `bitcoin::TxIn` does not include the amount, it just
    // references the `previous_output`'s `TxId` and `vout`. There may
    // be a better way of modelling each input than `(TxIn, Amount)`.
    pub fn new(
        (X_self, (tid_self, amount_self)): (PublicKey, (TxIn, Amount)),
        (X_other, (tid_other, amount_other)): (PublicKey, (TxIn, Amount)),
    ) -> anyhow::Result<Self> {
        let descriptor =
            Self::descriptor(&X_self, &X_other).context("failed to build descriptor")?;

        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![tid_self.clone(), tid_other],
            output: vec![TxOut {
                value: (amount_self + amount_other).as_sat(),
                script_pubkey: descriptor.script_pubkey(),
            }],
        };

        Ok(Self(transaction))
    }

    pub fn as_txin(&self) -> TxIn {
        TxIn {
            previous_output: OutPoint::new(self.0.txid(), 0),
            script_sig: Script::new(),
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        }
    }

    pub fn value(&self) -> Amount {
        Amount::from_sat(self.0.output[0].value)
    }

    fn descriptor(
        X_0: &secp256k1::PublicKey,
        X_1: &secp256k1::PublicKey,
    ) -> anyhow::Result<miniscript::Descriptor<bitcoin::PublicKey>> {
        let X_0 = hex::encode(X_0.serialize().to_vec());
        let X_1 = hex::encode(X_1.serialize().to_vec());

        // Describes the spending policy of the channel fund transaction T_f.
        //
        // For now we use `and(x_0, x_1)` - eventually we might want to replace this with a threshold signature.
        let descriptor_str = format!("and(pk({}),pk({}))", X_0, X_1,);
        let policy = miniscript::policy::Concrete::<bitcoin::PublicKey>::from_str(&descriptor_str)?;
        let miniscript = policy.compile()?;
        let descriptor = miniscript::Descriptor::Wsh(miniscript);

        Ok(descriptor)
    }
}

pub struct CommitTransaction {
    inner: Transaction,
    digest: SigHash,
}

impl CommitTransaction {
    // TODO: Handle expiry by passing it as an argument
    pub fn new(
        TX_f: &FundingTransaction,
        (_X_0, _R_0, _Y_0): (PublicKey, RevocationPublicKey, PublishingPublicKey),
        (_X_1, _R_1, _Y_1): (PublicKey, RevocationPublicKey, PublishingPublicKey),
    ) -> Self {
        let input = TX_f.as_txin();
        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input],
            // This output is the same as the input, except for the
            // spending conditions
            output: vec![TxOut {
                value: TX_f.value().as_sat(),
                script_pubkey: todo!(
                    "Use Miniscript to generate the transaction output with three
                 spending conditions using (X_0, R_0, Y_0) and (X_1, R_1, Y_1)"
                ),
            }],
        };

        let digest = SighashComponents::new(&transaction).sighash_all(
            &input,
            // TODO: May need to instead call `.witness_script()` on the
            // descriptor used to produce the `FundingTransaction`'s output
            // `script_pubkey`
            &input.script_sig,
            TX_f.value().as_sat(),
        );

        Self {
            inner: transaction,
            digest,
        }
    }

    /// Sign the commit transaction.
    ///
    /// Each party must ensure that they pass the arguments in the
    /// same order that they did when calling
    /// `FundingTransaction::new`.
    pub fn sign(
        mut self,
        (_X_0, _sig_0): (PublicKey, secp256k1::Signature),
        (_X_1, _sig_1): (PublicKey, secp256k1::Signature),
    ) -> anyhow::Result<Self> {
        // NOTE: Could return a `SignedCommitTransaction` for extra type
        // safety.
        todo!("Use Miniscript's `satisfy` API")
    }

    pub fn as_txin(&self) -> TxIn {
        TxIn {
            previous_output: OutPoint::new(self.inner.txid(), 0),
            script_sig: Script::new(),
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        }
    }

    pub fn value(&self) -> Amount {
        Amount::from_sat(self.inner.output[0].value)
    }

    pub fn digest(&self) -> SigHash {
        self.digest
    }
}

pub struct SplitTransaction {
    inner: Transaction,
    digest: SigHash,
}

impl SplitTransaction {
    pub fn new(
        TX_c: &CommitTransaction,
        ChannelState {
            party_0: (amount_0, X_0),
            party_1: (amount_1, X_1),
        }: ChannelState,
    ) -> Self {
        let input = TX_c.as_txin();

        let output_0 = TxOut {
            value: amount_0.as_sat(),
            script_pubkey: todo!(
                "Use Miniscript to generate based on providing a signature w.r.t. X_0"
            ),
        };

        let output_1 = TxOut {
            value: amount_1.as_sat(),
            script_pubkey: todo!(
                "Use Miniscript to generate based on providing a signature w.r.t. X_1"
            ),
        };

        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input],
            output: vec![output_0, output_1],
        };

        let digest = SighashComponents::new(&transaction).sighash_all(
            &input,
            // TODO: May need to instead call `.witness_script()` on the
            // descriptor used to produce the `CommitTransaction`'s output
            // `script_pubkey`
            &input.script_sig,
            TX_c.value().as_sat(),
        );

        Self {
            inner: transaction,
            digest,
        }
    }

    pub fn digest(&self) -> SigHash {
        self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_to_witness_script() {
        let X_0 = secp256k1::PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .expect("key 0");
        let X_1 = secp256k1::PublicKey::from_str(
            "022222222222222222222222222222222222222222222222222222222222222222",
        )
        .expect("key 1");
        let descriptor = FundingTransaction::descriptor(&X_0, &X_1).unwrap();

        let witness_script = format!("{}", descriptor.witness_script());
        assert_eq!(witness_script, "Script(OP_PUSHBYTES_33 0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166 OP_CHECKSIGVERIFY OP_PUSHBYTES_33 022222222222222222222222222222222222222222222222222222222222222222 OP_CHECKSIG)");
    }
}
