use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    TX_FEE,
};
use anyhow::bail;
use bitcoin::{
    hashes::{hash160, Hash},
    secp256k1,
    util::{bip143::SighashComponents, psbt::PartiallySignedTransaction},
    Address, Amount, Network, OutPoint, Script, SigHash, Transaction, TxIn, TxOut, Txid,
};
use ecdsa_fun::{
    self,
    adaptor::{Adaptor, EncryptedSignature},
    nonce::Deterministic,
    Signature,
};
use miniscript::{self, Descriptor, Segwitv0};
use sha2::Sha256;
use std::{collections::HashMap, str::FromStr};

#[derive(Clone, Debug)]
pub struct FundOutput(miniscript::Descriptor<bitcoin::PublicKey>);

impl FundOutput {
    pub fn new(Xs: [OwnershipPublicKey; 2]) -> Self {
        let descriptor = FundingTransaction::build_output_descriptor(Xs);

        Self(descriptor)
    }

    fn descriptor(&self) -> miniscript::Descriptor<bitcoin::PublicKey> {
        self.0.clone()
    }

    pub fn address(&self) -> Address {
        self.0.address(Network::Regtest).expect("cannot fail")
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, PartialEq, Debug)]
pub struct FundingTransaction {
    inner: Transaction,
    fund_output_descriptor: miniscript::Descriptor<bitcoin::PublicKey>,
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
    amount_a: Amount,
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
    amount_b: Amount,
}

impl FundingTransaction {
    pub fn new(
        (X_0, tid_0, amount_0): (OwnershipPublicKey, PartiallySignedTransaction, Amount),
        (X_1, tid_1, amount_1): (OwnershipPublicKey, PartiallySignedTransaction, Amount),
    ) -> anyhow::Result<Self> {
        let fund_output = FundOutput::new([X_0, X_1]);
        let fund_output_descriptor = fund_output.descriptor();

        let Transaction {
            input: input_a,
            output,
            ..
        } = tid_0.extract_tx();

        let change_outputs_a = output
            .into_iter()
            .filter(|output| output.script_pubkey != fund_output_descriptor.script_pubkey())
            .collect();

        let Transaction {
            input: input_b,
            output,
            ..
        } = tid_1.extract_tx();

        let change_outputs_b = output
            .into_iter()
            .filter(|output| output.script_pubkey != fund_output_descriptor.script_pubkey())
            .collect();

        let fund_output = TxOut {
            value: (amount_0 + amount_1).as_sat(),
            script_pubkey: fund_output_descriptor.script_pubkey(),
        };

        let TX_f = {
            // Sort the inputs by ascending order of previous_outputs (this order is defined
            // by rust-bitcoin as lexicographical order of txid and, if needed, numerical
            // order of vout). Both parties _must_ do this so that they compute the same
            // funding transaction
            let mut input = vec![input_a, input_b].concat();
            input.sort_by(|a, b| a.previous_output.cmp(&b.previous_output));

            // Sort the outputs by ascending lexicographical order of script_pubkey bytes.
            // Both parties _must_ do this so that they compute the same funding transaction
            let mut output = vec![vec![fund_output], change_outputs_a, change_outputs_b].concat();
            output.sort_by(|a, b| a.script_pubkey.cmp(&b.script_pubkey));

            Transaction {
                version: 2,
                lock_time: 0,
                input,
                output,
            }
        };

        Ok(Self {
            inner: TX_f,
            fund_output_descriptor,
            amount_a: amount_0,
            amount_b: amount_1,
        })
    }

    pub fn as_txin(&self) -> TxIn {
        #[allow(clippy::cast_possible_truncation)]
        let fund_output_index = self
            .inner
            .output
            .iter()
            .position(|output| output.script_pubkey == self.fund_output_descriptor.script_pubkey())
            .expect("cannot fail") as u32;

        TxIn {
            previous_output: OutPoint::new(self.inner.txid(), fund_output_index),
            script_sig: Script::new(),
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        }
    }

    pub fn amount_a(&self) -> Amount {
        self.amount_a
    }

    pub fn amount_b(&self) -> Amount {
        self.amount_b
    }

    pub fn value(&self) -> Amount {
        self.amount_a + self.amount_b
    }

    pub fn fund_output_descriptor(&self) -> miniscript::Descriptor<bitcoin::PublicKey> {
        self.fund_output_descriptor.clone()
    }

    pub fn into_psbt(self) -> anyhow::Result<PartiallySignedTransaction> {
        PartiallySignedTransaction::from_unsigned_tx(self.inner)
            .map_err(|_| anyhow::anyhow!("could not convert to psbt"))
    }

    pub fn txid(&self) -> Txid {
        self.inner.txid()
    }

    fn build_output_descriptor(
        mut Xs: [OwnershipPublicKey; 2],
    ) -> miniscript::Descriptor<bitcoin::PublicKey> {
        // Decide which subscript (either `_0` or `_1`) to assign to each ownership
        // public key based on their ascending lexicographical order of bytes. Both
        // parties _must_ do this so that they compute the same fund transaction output
        // descriptor
        Xs.sort_by(|a, b| a.partial_cmp(b).expect("comparison is possible"));
        let [X_0, X_1] = Xs;

        // Describes the spending policy of the channel fund transaction TX_f.
        // For now we use `and(X_0, X_1)` - eventually we might want to replace this
        // with a threshold signature.
        const MINISCRIPT_TEMPLATE: &str = "c:and_v(v:pk(X_0),pk_k(X_1))";

        let X_0 = hex::encode(secp256k1::PublicKey::from(X_0).serialize().to_vec());
        let X_1 = hex::encode(secp256k1::PublicKey::from(X_1).serialize().to_vec());

        let miniscript = MINISCRIPT_TEMPLATE
            .replace("X_0", &X_0)
            .replace("X_1", &X_1);

        let miniscript =
            miniscript::Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str(&miniscript)
                .expect("a valid miniscript");

        miniscript::Descriptor::Wsh(miniscript)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct CommitTransaction {
    inner: Transaction,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
    output_descriptor: Descriptor<bitcoin::PublicKey>,
    time_lock: u32,
    digest: SigHash,
}

impl CommitTransaction {
    pub fn new(
        TX_f: &FundingTransaction,
        keys: &[(OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey); 2],
        time_lock: u32,
    ) -> anyhow::Result<Self> {
        let output_descriptor = Self::build_descriptor(keys, time_lock)?;

        let input = TX_f.as_txin();
        let TX_c = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input],
            // This output is the same as the input, except for the
            // spending conditions
            output: vec![TxOut {
                value: TX_f.value().as_sat() - TX_FEE,
                script_pubkey: output_descriptor.script_pubkey(),
            }],
        };

        let digest = Self::compute_digest(&TX_c, TX_f);

        let input_descriptor = TX_f.fund_output_descriptor();

        Ok(Self {
            inner: TX_c,
            input_descriptor,
            output_descriptor,
            time_lock,
            digest,
        })
    }

    pub fn encsign_once(
        &self,
        x_self: OwnershipKeyPair,
        Y_other: PublishingPublicKey,
    ) -> EncryptedSignature {
        x_self.encsign(Y_other, self.digest)
    }

    pub fn sign(&self, x_self: &OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    /// Add signatures to CommitTransaction.
    pub fn add_signatures(
        self,
        (X_0, sig_0): (OwnershipPublicKey, Signature),
        (X_1, sig_1): (OwnershipPublicKey, Signature),
    ) -> anyhow::Result<Transaction> {
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

        let mut TX_c = self.inner;
        self.input_descriptor
            .satisfy(&mut TX_c.input[0], satisfier)?;

        Ok(TX_c)
    }

    /// Use `CommitTransaction` as a Transaction Input for the
    /// `SplitTransaction`. The sequence number is set to the value of
    /// `time_lock` since the `SplitTransaction` uses the time-locked path
    /// of the `CommitTransaction`'s script.
    pub fn as_txin_for_TX_s(&self) -> TxIn {
        TxIn {
            previous_output: OutPoint::new(self.inner.txid(), 0),
            script_sig: Script::new(),
            sequence: self.time_lock,
            witness: Vec::new(),
        }
    }

    /// Use `CommitTransaction` as a Transaction Input for the
    /// `PunishTransaction`. The sequence number is set to `OxFFFF_FFFF` since
    /// the `PunishTransaction` does not use the time-locked path of the
    /// `CommitTransaction`'s script.
    pub fn as_txin_for_TX_p(&self) -> TxIn {
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

    pub fn output_descriptor(&self) -> Descriptor<bitcoin::PublicKey> {
        self.output_descriptor.clone()
    }

    pub fn digest(&self) -> SigHash {
        self.digest
    }

    pub fn txid(&self) -> Txid {
        self.inner.txid()
    }

    fn compute_digest(TX_c: &Transaction, TX_f: &FundingTransaction) -> SigHash {
        SighashComponents::new(&TX_c).sighash_all(
            &TX_f.as_txin(),
            &TX_f.fund_output_descriptor().witness_script(),
            TX_f.value().as_sat(),
        )
    }

    fn build_descriptor(
        keys: &[(OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey); 2],
        time_lock: u32,
    ) -> anyhow::Result<Descriptor<bitcoin::PublicKey>> {
        // Decide which subscript (either `_0` or `_1`) to assign to each group of keys
        // based on comparing the ownership public keys in ascending
        // lexicographical order of bytes. Both parties _must_ do this so that
        // they compute the same commit transaction output descriptor
        let (X, R, Y) = match keys[0]
            .0
            .partial_cmp(&keys[1].0)
            .expect("comparison is possible")
        {
            std::cmp::Ordering::Less => (
                (keys[0].0.clone(), keys[1].0.clone()),
                (keys[0].1.clone(), keys[1].1.clone()),
                (keys[0].2.clone(), keys[1].2.clone()),
            ),
            _ => (
                (keys[1].0.clone(), keys[0].0.clone()),
                (keys[1].1.clone(), keys[0].1.clone()),
                (keys[1].2.clone(), keys[0].2.clone()),
            ),
        };

        let X_0 = bitcoin::secp256k1::PublicKey::from(X.0);
        let X_1 = bitcoin::secp256k1::PublicKey::from(X.1);
        let R_0 = bitcoin::secp256k1::PublicKey::from(R.0);
        let R_1 = bitcoin::secp256k1::PublicKey::from(R.1);
        let Y_0 = bitcoin::secp256k1::PublicKey::from(Y.0);
        let Y_1 = bitcoin::secp256k1::PublicKey::from(Y.1);

        let X_0_hash = hash160::Hash::hash(&X_0.serialize()[..]);
        let X_0 = hex::encode(X_0.serialize().to_vec());
        let X_1_hash = hash160::Hash::hash(&X_1.serialize()[..]);
        let X_1 = hex::encode(X_1.serialize().to_vec());

        let R_0_hash = hash160::Hash::hash(&R_0.serialize()[..]);
        let R_1_hash = hash160::Hash::hash(&R_1.serialize()[..]);

        let Y_0_hash = hash160::Hash::hash(&Y_0.serialize()[..]);
        let Y_1_hash = hash160::Hash::hash(&Y_1.serialize()[..]);

        // Describes the spending policy of the channel commit transaction TX_c.
        // There are three possible way to spend this transaction:
        // 1. Channel state: It is correctly signed w.r.t X_0, X_1 and after relative
        // timelock
        // 2. Punish 0: It is correctly signed w.r.t X_1, Y_0, R_0
        // 3. Punish 1: It is correctly signed w.r.t X_0, Y_1, R_1

        // Policy is or(and(older(144),and(pk(X0),pk(X1))),or(and(pk(X1),and(pk(Y0),
        // pk(R0))),and(pk(X0),and(pk(Y1),pk(R1)))))

        let channel_state_condition = format!(
            "and_v(v:older({}),and_v(v:pk({}),pk_k({})))",
            time_lock, X_0, X_1
        );
        let punish_0_condition = format!(
            "and_v(v:pkh({}),and_v(v:pkh({}),pk_h({})))",
            X_1_hash, Y_0_hash, R_0_hash
        );
        let punish_1_condition = format!(
            "and_v(v:pkh({}),and_v(v:pkh({}),pk_h({})))",
            X_0_hash, Y_1_hash, R_1_hash
        );
        let descriptor_str = format!(
            "wsh(c:or_i(or_i({},{}),{}))",
            punish_0_condition, punish_1_condition, channel_state_condition
        );
        let descriptor = Descriptor::<bitcoin::PublicKey>::from_str(&descriptor_str)?;

        Ok(descriptor)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct SplitTransaction {
    inner: Transaction,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
    digest: SigHash,
}

impl SplitTransaction {
    // TODO: Validate that TX_c as input can pay for outputs + fees.
    pub fn new(
        TX_c: &CommitTransaction,
        amount_a: Amount,
        address_a: Address,
        amount_b: Amount,
        address_b: Address,
    ) -> Self {
        let input = TX_c.as_txin_for_TX_s();

        // Distribute transaction fee costs evenly between outputs
        let half_fee = TX_FEE / 2;

        let output_a = TxOut {
            value: amount_a.as_sat() - half_fee,
            script_pubkey: address_a.script_pubkey(),
        };

        let output_b = TxOut {
            value: amount_b.as_sat() - half_fee,
            script_pubkey: address_b.script_pubkey(),
        };

        let TX_s = {
            // Sort the outputs by ascending lexicographical order of script_pubkey bytes.
            // Both parties _must_ do this so that they compute the same funding transaction
            let mut output = vec![output_a, output_b];
            output.sort_by(|a, b| a.script_pubkey.cmp(&b.script_pubkey));

            Transaction {
                version: 2,
                lock_time: 0,
                input: vec![input],
                output,
            }
        };

        let digest = Self::compute_digest(&TX_s, TX_c);

        let input_descriptor = TX_c.output_descriptor();

        Self {
            inner: TX_s,
            input_descriptor,
            digest,
        }
    }

    pub fn sign_once(&self, x_self: OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    // TODO: Expose verify sig directly on Transaction.
    pub fn digest(&self) -> SigHash {
        self.digest
    }

    /// Add signatures to SplitTransaction.
    pub fn add_signatures(
        &mut self,
        (X_0, sig_0): (OwnershipPublicKey, Signature),
        (X_1, sig_1): (OwnershipPublicKey, Signature),
    ) -> anyhow::Result<()> {
        struct Satisfier {
            a: (bitcoin::PublicKey, bitcoin::secp256k1::Signature),
            b: (bitcoin::PublicKey, bitcoin::secp256k1::Signature),
        }

        impl miniscript::Satisfier<bitcoin::PublicKey> for Satisfier {
            fn lookup_sig(&self, pk: &bitcoin::PublicKey) -> Option<miniscript::BitcoinSig> {
                if &self.a.0 == pk {
                    return Some((self.a.1, bitcoin::SigHashType::All));
                }

                if &self.b.0 == pk {
                    return Some((self.b.1, bitcoin::SigHashType::All));
                }

                None
            }

            fn check_older(&self, _: u32) -> bool {
                true
            }
        }

        let X_0 = ::bitcoin::PublicKey {
            compressed: true,
            key: X_0.into(),
        };
        let X_1 = ::bitcoin::PublicKey {
            compressed: true,
            key: X_1.into(),
        };

        let satisfier = Satisfier {
            a: (X_0, sig_0.into()),
            b: (X_1, sig_1.into()),
        };

        self.input_descriptor
            .satisfy(&mut self.inner.input[0], satisfier)?;

        Ok(())
    }

    fn compute_digest(TX_s: &Transaction, TX_c: &CommitTransaction) -> SigHash {
        SighashComponents::new(&TX_s).sighash_all(
            &TX_c.as_txin_for_TX_s(),
            &TX_c.output_descriptor().witness_script(),
            TX_c.value().as_sat(),
        )
    }
}

impl From<SplitTransaction> for Transaction {
    fn from(from: SplitTransaction) -> Self {
        from.inner
    }
}

#[derive(Clone, Debug)]
pub struct PunishTransaction(Transaction);

#[derive(Debug, thiserror::Error)]
pub enum PunishError {
    #[error("no signatures found in witness stack")]
    NoSignatures,
    #[error("could not recover PublishingSecretKey from signatures in transaction")]
    RecoveryFailure,
}

impl PunishTransaction {
    pub fn new(
        x_self: &OwnershipKeyPair,
        final_address: Address,
        TX_c: &CommitTransaction,
        encsig_TX_c_self: &EncryptedSignature,
        r_other: &RevocationKeyPair,
        Y_other: PublishingPublicKey,
        revoked_TX_c_candidate: Transaction,
    ) -> anyhow::Result<Self> {
        let adaptor = Adaptor::<Sha256, Deterministic<Sha256>>::default();

        // CommitTransaction's only have one input
        let input = revoked_TX_c_candidate.input[0].clone();

        // Extract all signatures from witness stack
        let mut sigs = Vec::new();
        for witness in input.witness.iter() {
            let witness = witness.as_slice();

            let res = bitcoin::secp256k1::Signature::from_der(&witness[..witness.len() - 1]);
            match res {
                Ok(sig) => sigs.push(sig),
                Err(_) => {
                    continue;
                }
            }
        }

        if sigs.is_empty() {
            bail!(PunishError::NoSignatures)
        }

        // Attempt to extract y_other from every signature
        let y_other = sigs
            .into_iter()
            .find_map(|sig| {
                adaptor
                    .recover_decryption_key(&Y_other.clone().into(), &sig.into(), &encsig_TX_c_self)
                    .map(PublishingKeyPair::from)
            })
            .ok_or_else(|| PunishError::RecoveryFailure)?;

        let mut TX_p = {
            let output = TxOut {
                value: TX_c.value().as_sat() - TX_FEE,
                script_pubkey: final_address.script_pubkey(),
            };
            Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TX_c.as_txin_for_TX_p()],
                output: vec![output],
            }
        };

        let digest = Self::compute_digest(&TX_p, &TX_c);

        let satisfier = {
            let mut satisfier = HashMap::with_capacity(3);

            let X_self = bitcoin::secp256k1::PublicKey::from(x_self.public());
            let X_self_hash = hash160::Hash::hash(&X_self.serialize()[..]);
            let X_self = bitcoin::PublicKey {
                compressed: true,
                key: X_self,
            };
            let sig_x_self = x_self.sign(digest);

            let Y_other = bitcoin::secp256k1::PublicKey::from(Y_other);
            let Y_other_hash = hash160::Hash::hash(&Y_other.serialize()[..]);
            let Y_other = bitcoin::PublicKey {
                compressed: true,
                key: Y_other,
            };
            let sig_y_other = y_other.sign(digest);

            let R_other = bitcoin::secp256k1::PublicKey::from(r_other.public());
            let R_other_hash = hash160::Hash::hash(&R_other.serialize()[..]);
            let R_other = bitcoin::PublicKey {
                compressed: true,
                key: R_other,
            };
            let sig_r_other = r_other.sign(digest);

            // The order in which these are inserted doesn't matter
            satisfier.insert(
                X_self_hash,
                (X_self, (sig_x_self.into(), ::bitcoin::SigHashType::All)),
            );
            satisfier.insert(
                Y_other_hash,
                (Y_other, (sig_y_other.into(), ::bitcoin::SigHashType::All)),
            );
            satisfier.insert(
                R_other_hash,
                (R_other, (sig_r_other.into(), ::bitcoin::SigHashType::All)),
            );

            satisfier
        };

        TX_c.output_descriptor()
            .satisfy(&mut TX_p.input[0], satisfier)?;

        Ok(Self(TX_p))
    }

    fn compute_digest(TX_p: &Transaction, TX_c: &CommitTransaction) -> SigHash {
        SighashComponents::new(&TX_p).sighash_all(
            &TX_c.as_txin_for_TX_p(),
            &TX_c.output_descriptor().witness_script(),
            TX_c.value().as_sat(),
        )
    }
}

impl From<PunishTransaction> for Transaction {
    fn from(from: PunishTransaction) -> Self {
        from.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CloseTransaction {
    inner: Transaction,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
    digest: SigHash,
}

impl CloseTransaction {
    pub fn new(
        TX_f: &FundingTransaction,
        amount_a: Amount,
        address_a: Address,
        amount_b: Amount,
        address_b: Address,
    ) -> Self {
        let input = TX_f.as_txin();

        // Distribute transaction fee costs evenly between outputs
        let half_fee = TX_FEE / 2;

        let output_a = TxOut {
            value: amount_a.as_sat() - half_fee,
            script_pubkey: address_a.script_pubkey(),
        };

        let output_b = TxOut {
            value: amount_b.as_sat() - half_fee,
            script_pubkey: address_b.script_pubkey(),
        };

        let close_transaction = {
            let mut output = vec![output_a, output_b];

            // Sort the outputs by ascending lexicographical order of script_pubkey bytes.
            // Both parties _must_ do this so that they compute the same close transaction
            output.sort_by(|a, b| a.script_pubkey.cmp(&b.script_pubkey));

            Transaction {
                version: 2,
                lock_time: 0,
                input: vec![input],
                output,
            }
        };

        let digest = Self::compute_digest(&close_transaction, &TX_f);

        Self {
            inner: close_transaction,
            input_descriptor: TX_f.fund_output_descriptor(),
            digest,
        }
    }

    fn compute_digest(close_transaction: &Transaction, TX_f: &FundingTransaction) -> SigHash {
        SighashComponents::new(&close_transaction).sighash_all(
            &TX_f.as_txin(),
            &TX_f.fund_output_descriptor().witness_script(),
            TX_f.value().as_sat(),
        )
    }

    pub fn digest(&self) -> SigHash {
        self.digest
    }

    pub fn add_signatures(
        self,
        (X_0, sig_0): (OwnershipPublicKey, Signature),
        (X_1, sig_1): (OwnershipPublicKey, Signature),
    ) -> anyhow::Result<Transaction> {
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

        let mut close_transaction = self.inner;
        self.input_descriptor
            .satisfy(&mut close_transaction.input[0], satisfier)?;

        Ok(close_transaction)
    }

    pub fn sign_once(&self, x_self: OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Miniscript compiler: ")]
    MiniscriptCompiler(#[from] miniscript::policy::compiler::CompilerError),
    #[error("Miniscript: ")]
    Miniscript(#[from] miniscript::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::point_from_str;
    use miniscript::Miniscript;

    #[test]
    fn compile_funding_transaction_spending_policy() {
        // Describes the spending policy of the fund transaction.
        // The resulting descriptor is hardcoded used above in the code
        let spending_policy = "and(pk(X_self),pk(X_other))";
        let policy = miniscript::policy::Concrete::<String>::from_str(spending_policy).unwrap();
        let miniscript: Miniscript<String, Segwitv0> = policy.compile().unwrap();

        let descriptor = format!("{}", miniscript);

        println!("{}", descriptor);
    }

    #[test]
    fn funding_descriptor_to_witness_script() {
        let X_0 =
            point_from_str("0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166")
                .unwrap()
                .into();
        let X_1 =
            point_from_str("022222222222222222222222222222222222222222222222222222222222222222")
                .unwrap()
                .into();
        let descriptor = FundingTransaction::build_output_descriptor([X_0, X_1]);

        let witness_script = format!("{}", descriptor.witness_script());
        assert_eq!(witness_script, "Script(OP_PUSHBYTES_33 0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166 OP_CHECKSIGVERIFY OP_PUSHBYTES_33 022222222222222222222222222222222222222222222222222222222222222222 OP_CHECKSIG)");
    }

    #[test]
    fn commitment_descriptor_to_witness_script() {
        let X_0 =
            point_from_str("032a34617a9141231baa27bcadf622322eed1e16b6036fdf15f42a85f7250c4823")
                .unwrap()
                .into();
        let R_0 =
            point_from_str("03ff65a7fedd9dc637bbaf3cbe4c5971de853e0c359195f19c57211fe0b96ab39e")
                .unwrap()
                .into();
        let Y_0 =
            point_from_str("03b3ee07bb851fec17e6cdb2dc235523555dc3193c2ff6399ef28ce941bc57b2b4")
                .unwrap()
                .into();
        let X_1 =
            point_from_str("03437a3813f17a264e2c8fc41fb0895634d34c7c9cb9147c553cc67ff37293b1cd")
                .unwrap()
                .into();
        let R_1 =
            point_from_str("02b637ba109a2a844b27d31c9ffac41bfe080d2f0256eeb03839d66442c4ce0deb")
                .unwrap()
                .into();
        let Y_1 =
            point_from_str("03851562dd136d68ff0911b4aa6b1ec95850144ddb939a1070159f0a4163d20895")
                .unwrap()
                .into();
        let time_lock = 144;

        let descriptor =
            CommitTransaction::build_descriptor(&[(X_0, R_0, Y_0), (X_1, R_1, Y_1)], time_lock)
                .unwrap();

        let witness_script = format!("{}", descriptor.witness_script());
        assert_eq!(witness_script, "Script(OP_IF OP_IF OP_DUP OP_HASH160 OP_PUSHBYTES_20 635de934904ad5406559beebcc3ca0d119721323 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 be60bbce0058cb25f268d70559e1a3433d75f557 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 4c8a3449333f92f386b4b8a202353719016261e8 OP_EQUALVERIFY OP_ELSE OP_DUP OP_HASH160 OP_PUSHBYTES_20 1b08ea4a2fbbe0121205f63068f78564ff204995 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 ea92d4bb15b4babd0c216c12f61fe7083ed06e3b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 565dd1650db6ffae1c2dd67d83a5709aa0ddd2e9 OP_EQUALVERIFY OP_ENDIF OP_ELSE OP_PUSHBYTES_2 9000 OP_CSV OP_VERIFY OP_PUSHBYTES_33 032a34617a9141231baa27bcadf622322eed1e16b6036fdf15f42a85f7250c4823 OP_CHECKSIGVERIFY OP_PUSHBYTES_33 03437a3813f17a264e2c8fc41fb0895634d34c7c9cb9147c553cc67ff37293b1cd OP_ENDIF OP_CHECKSIG)");
    }
}
