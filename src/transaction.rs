use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    SplitOutputs,
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

// TODO: We could handle fees dynamically

/// Flat fee used for all transactions involved in the protocol. Satoshi is the
/// unit used.
const TX_FEE: u64 = 10_000;

#[derive(Debug, Clone)]
pub struct FundOutput(Address);

impl FundOutput {
    pub fn new(X_a: OwnershipPublicKey, X_b: OwnershipPublicKey) -> Self {
        let descriptor = FundingTransaction::build_output_descriptor(&X_a.into(), &X_b.into());
        let address = descriptor.address(Network::Regtest).expect("cannot fail");

        Self(address)
    }

    pub fn address(&self) -> Address {
        self.0.clone()
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct FundingTransaction {
    inner: Transaction,
    fund_output_descriptor: miniscript::Descriptor<bitcoin::PublicKey>,
    amount_a: Amount,
    amount_b: Amount,
}

impl FundingTransaction {
    pub fn new(
        (X_a, tid_a, amount_a): (OwnershipPublicKey, PartiallySignedTransaction, Amount),
        (X_b, tid_b, amount_b): (OwnershipPublicKey, PartiallySignedTransaction, Amount),
    ) -> anyhow::Result<Self> {
        let fund_output_descriptor =
            FundingTransaction::build_output_descriptor(&X_a.into(), &X_b.into());

        let Transaction {
            input: input_a,
            output,
            ..
        } = tid_a.extract_tx();

        let change_outputs_a = output
            .into_iter()
            .filter(|output| output.script_pubkey != fund_output_descriptor.script_pubkey())
            .collect();

        let Transaction {
            input: input_b,
            output,
            ..
        } = tid_b.extract_tx();

        let change_outputs_b = output
            .into_iter()
            .filter(|output| output.script_pubkey != fund_output_descriptor.script_pubkey())
            .collect();

        let fund_output = TxOut {
            value: (amount_a + amount_b).as_sat(),
            script_pubkey: fund_output_descriptor.script_pubkey(),
        };

        let TX_f = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input_a, input_b].concat(),
            output: vec![vec![fund_output], change_outputs_a, change_outputs_b].concat(),
        };

        Ok(Self {
            inner: TX_f,
            fund_output_descriptor,
            amount_a,
            amount_b,
        })
    }

    pub fn as_txin(&self) -> TxIn {
        let fund_output_index = self
            .inner
            .output
            .iter()
            .position(|output| output.script_pubkey == self.fund_output_descriptor.script_pubkey())
            .expect("cannot fail");

        TxIn {
            previous_output: OutPoint::new(self.inner.txid(), fund_output_index as u32),
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

    fn build_output_descriptor(
        X_a: &secp256k1::PublicKey,
        X_b: &secp256k1::PublicKey,
    ) -> miniscript::Descriptor<bitcoin::PublicKey> {
        // Describes the spending policy of the channel fund transaction TX_f.
        // For now we use `and(X_a, X_b)` - eventually we might want to replace this
        // with a threshold signature.
        const MINISCRIPT_TEMPLATE: &str = "c:and_v(v:pk(X_a),pk_k(X_b))";

        let X_a = hex::encode(X_a.serialize().to_vec());
        let X_b = hex::encode(X_b.serialize().to_vec());

        let miniscript = MINISCRIPT_TEMPLATE
            .replace("X_a", &X_a)
            .replace("X_b", &X_b);

        let miniscript =
            miniscript::Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str(&miniscript)
                .expect("a valid miniscript");

        miniscript::Descriptor::Wsh(miniscript)
    }
}

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
        (X_a, R_a, Y_a): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        (X_b, R_b, Y_b): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        time_lock: u32,
    ) -> anyhow::Result<Self> {
        let output_descriptor =
            Self::build_descriptor((X_a, R_a, Y_a), (X_b, R_b, Y_b), time_lock)?;

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
        (X_a, sig_a): (OwnershipPublicKey, Signature),
        (X_b, sig_b): (OwnershipPublicKey, Signature),
    ) -> anyhow::Result<Transaction> {
        let satisfier = {
            let mut satisfier = HashMap::with_capacity(2);

            let X_a = ::bitcoin::PublicKey {
                compressed: true,
                key: X_a.into(),
            };
            let X_b = ::bitcoin::PublicKey {
                compressed: true,
                key: X_b.into(),
            };

            // NOTE: The order hopefully doesn't matter
            satisfier.insert(X_a, (sig_a.into(), ::bitcoin::SigHashType::All));
            satisfier.insert(X_b, (sig_b.into(), ::bitcoin::SigHashType::All));

            satisfier
        };

        let mut TX_c = self.inner;
        self.input_descriptor
            .satisfy(&mut TX_c.input[0], satisfier)?;

        Ok(TX_c)
    }

    /// Use `CommitTransaction` as a Transaction Input for the
    /// `SplitTransaction`. The sequence number is set to the value of
    /// `time_lock` since the `SplitTransaction` uses the
    /// time-locked path of the `CommitTransaction`'s script.
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
        (X_0, R_0, Y_0): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        (X_1, R_1, Y_1): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        time_lock: u32,
    ) -> anyhow::Result<Descriptor<bitcoin::PublicKey>> {
        let X_0 = bitcoin::secp256k1::PublicKey::from(X_0);
        let R_0 = bitcoin::secp256k1::PublicKey::from(R_0);
        let Y_0 = bitcoin::secp256k1::PublicKey::from(Y_0);

        let X_1 = bitcoin::secp256k1::PublicKey::from(X_1);
        let R_1 = bitcoin::secp256k1::PublicKey::from(R_1);
        let Y_1 = bitcoin::secp256k1::PublicKey::from(Y_1);

        let X_0_hash = hash160::Hash::hash(&X_0.serialize()[..]);
        let X_0 = hex::encode(X_0.serialize().to_vec());
        let X_1_hash = hash160::Hash::hash(&X_1.serialize()[..]);
        let X_1 = hex::encode(X_1.serialize().to_vec());

        let R_0_hash = hash160::Hash::hash(&R_0.serialize()[..]);
        let R_1_hash = hash160::Hash::hash(&R_1.serialize()[..]);

        let Y_0_hash = hash160::Hash::hash(&Y_0.serialize()[..]);
        let Y_1_hash = hash160::Hash::hash(&Y_1.serialize()[..]);

        // Describes the spending policy of the channel commit transaction T_c.
        // There are possible way to spend this transaction:
        // 1. Channel state: It is correctly signed w.r.t pk_0, pk_1 and after relative
        // timelock
        // 2. Punish 0: It is correctly signed w.r.t pk_1, Y_0, R_0
        // 3. Punish 1: It is correctly signed w.r.t pk_0, Y_1, R_1

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

#[derive(Clone, Debug, PartialEq)]
pub struct SplitTransaction {
    #[cfg(test)]
    pub inner: Transaction,
    #[cfg(not(test))]
    inner: Transaction,
    input_descriptor: Descriptor<bitcoin::PublicKey>,
    digest: SigHash,
    outputs: SplitOutputs,
}

impl SplitTransaction {
    pub fn new(TX_c: &CommitTransaction, outputs: SplitOutputs) -> Self {
        let SplitOutputs {
            a: (amount_a, X_a),
            b: (amount_b, X_b),
        } = outputs.clone();

        let input = TX_c.as_txin_for_TX_s();

        // TODO: Maybe we should spend directly to an address owned by the wallet

        let descriptor = SplitTransaction::wpk_descriptor(X_a);
        let output_a = TxOut {
            value: amount_a.as_sat() - TX_FEE,
            script_pubkey: descriptor.script_pubkey(),
        };

        let descriptor = SplitTransaction::wpk_descriptor(X_b);
        let output_b = TxOut {
            value: amount_b.as_sat() - TX_FEE,
            script_pubkey: descriptor.script_pubkey(),
        };

        let TX_s = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input],
            output: vec![output_a, output_b],
        };

        let digest = Self::compute_digest(&TX_s, TX_c);

        let input_descriptor = TX_c.output_descriptor();

        Self {
            inner: TX_s,
            input_descriptor,
            digest,
            outputs,
        }
    }

    pub fn sign_once(&self, x_self: OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    pub fn outputs(&self) -> SplitOutputs {
        self.outputs.clone()
    }

    pub fn digest(&self) -> SigHash {
        self.digest
    }

    /// Add signatures to SplitTransaction.
    pub fn add_signatures(
        &mut self,
        (X_a, sig_a): (OwnershipPublicKey, Signature),
        (X_b, sig_b): (OwnershipPublicKey, Signature),
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

        let X_a = ::bitcoin::PublicKey {
            compressed: true,
            key: X_a.into(),
        };
        let X_b = ::bitcoin::PublicKey {
            compressed: true,
            key: X_b.into(),
        };

        let satisfier = Satisfier {
            a: (X_a, sig_a.into()),
            b: (X_b, sig_b.into()),
        };

        self.input_descriptor
            .satisfy(&mut self.inner.input[0], satisfier)?;

        Ok(())
    }

    fn wpk_descriptor(key: OwnershipPublicKey) -> miniscript::Descriptor<bitcoin::PublicKey> {
        let pk = bitcoin::PublicKey {
            key: key.into(),
            compressed: true,
        };

        miniscript::Descriptor::Wpkh(pk)
    }

    fn compute_digest(TX_s: &Transaction, TX_c: &CommitTransaction) -> SigHash {
        SighashComponents::new(&TX_s).sighash_all(
            &TX_c.as_txin_for_TX_s(),
            &TX_c.output_descriptor().witness_script(),
            TX_c.value().as_sat(),
        )
    }
}

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
        revoked_TX_c_candidate: Transaction,
        TX_c: CommitTransaction,
        Y_other: PublishingPublicKey,
        encsig_TX_c_self: EncryptedSignature,
        r_other: RevocationKeyPair,
        x_self: OwnershipKeyPair,
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
            let output_descriptor = PunishTransaction::wpk_descriptor(x_self.public());
            let output = TxOut {
                value: TX_c.value().as_sat() - TX_FEE,
                script_pubkey: output_descriptor.script_pubkey(),
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

            // NOTE: The order hopefully doesn't matter
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

    fn wpk_descriptor(key: OwnershipPublicKey) -> miniscript::Descriptor<bitcoin::PublicKey> {
        let pk = bitcoin::PublicKey {
            key: key.into(),
            compressed: true,
        };

        miniscript::Descriptor::Wpkh(pk)
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
        (amount_a, output_a): (Amount, Address),
        (amount_b, output_b): (Amount, Address),
    ) -> Self {
        let output_a = TxOut {
            value: amount_a.as_sat() - 10_000,
            script_pubkey: output_a.script_pubkey(),
        };

        let output_b = TxOut {
            value: amount_b.as_sat() - 10_000,
            script_pubkey: output_b.script_pubkey(),
        };

        let closing_transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TX_f.as_txin()],
            output: vec![output_a, output_b],
        };

        let digest = Self::compute_digest(&closing_transaction, TX_f);

        Self {
            inner: closing_transaction,
            input_descriptor: TX_f.fund_output_descriptor(),
            digest,
        }
    }

    fn compute_digest(closing_transaction: &Transaction, TX_f: &FundingTransaction) -> SigHash {
        SighashComponents::new(&closing_transaction).sighash_all(
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
        (X_a, sig_a): (OwnershipPublicKey, Signature),
        (X_b, sig_b): (OwnershipPublicKey, Signature),
    ) -> anyhow::Result<Transaction> {
        let satisfier = {
            let mut satisfier = HashMap::with_capacity(2);

            let X_a = ::bitcoin::PublicKey {
                compressed: true,
                key: X_a.into(),
            };
            let X_b = ::bitcoin::PublicKey {
                compressed: true,
                key: X_b.into(),
            };

            satisfier.insert(X_a, (sig_a.into(), ::bitcoin::SigHashType::All));
            satisfier.insert(X_b, (sig_b.into(), ::bitcoin::SigHashType::All));

            satisfier
        };

        let mut closing_transaction = self.inner;
        self.input_descriptor
            .satisfy(&mut closing_transaction.input[0], satisfier)?;

        Ok(closing_transaction)
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
pub fn input_psbt(
    output_amount: Amount,
    X_alice: OwnershipPublicKey,
    X_bob: OwnershipPublicKey,
) -> PartiallySignedTransaction {
    let output = FundOutput::new(X_alice, X_bob);
    let transaction = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: 0xFFFF_FFFF,
            witness: Vec::new(),
        }],
        output: vec![TxOut {
            value: output_amount.as_sat(),
            script_pubkey: output.address().script_pubkey(),
        }],
    };

    PartiallySignedTransaction::from_unsigned_tx(transaction).unwrap()
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
        let X_0 = secp256k1::PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .expect("key 0");
        let X_1 = secp256k1::PublicKey::from_str(
            "022222222222222222222222222222222222222222222222222222222222222222",
        )
        .expect("key 1");
        let descriptor = FundingTransaction::build_output_descriptor(&X_0, &X_1);

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
            CommitTransaction::build_descriptor((X_0, R_0, Y_0), (X_1, R_1, Y_1), time_lock)
                .unwrap();

        let witness_script = format!("{}", descriptor.witness_script());
        assert_eq!(witness_script, "Script(OP_IF OP_IF OP_DUP OP_HASH160 OP_PUSHBYTES_20 635de934904ad5406559beebcc3ca0d119721323 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 be60bbce0058cb25f268d70559e1a3433d75f557 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 4c8a3449333f92f386b4b8a202353719016261e8 OP_EQUALVERIFY OP_ELSE OP_DUP OP_HASH160 OP_PUSHBYTES_20 1b08ea4a2fbbe0121205f63068f78564ff204995 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 ea92d4bb15b4babd0c216c12f61fe7083ed06e3b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 565dd1650db6ffae1c2dd67d83a5709aa0ddd2e9 OP_EQUALVERIFY OP_ENDIF OP_ELSE OP_PUSHBYTES_2 9000 OP_CSV OP_VERIFY OP_PUSHBYTES_33 032a34617a9141231baa27bcadf622322eed1e16b6036fdf15f42a85f7250c4823 OP_CHECKSIGVERIFY OP_PUSHBYTES_33 03437a3813f17a264e2c8fc41fb0895634d34c7c9cb9147c553cc67ff37293b1cd OP_ENDIF OP_CHECKSIG)");
    }
}
