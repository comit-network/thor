use crate::{
    keys::{PublicKey, PublishingPublicKey, RevocationPublicKey},
    ChannelState,
};
use bitcoin::{
    secp256k1, util::bip143::SighashComponents, Amount, OutPoint, Script, SigHash, Transaction,
    TxIn, TxOut,
};
use miniscript::Segwitv0;
use std::str::FromStr;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct FundingTransaction(Transaction);

impl FundingTransaction {
    // A `bitcoin::TxIn` does not include the amount, it just
    // references the `previous_output`'s `TxId` and `vout`. There may
    // be a better way of modelling each input than `(TxIn, Amount)`.
    pub fn new(
        (_X_self, (tid_self, amount_self)): (PublicKey, (TxIn, Amount)),
        (_X_other, (tid_other, amount_other)): (PublicKey, (TxIn, Amount)),
        descriptor: miniscript::Descriptor<bitcoin::PublicKey>,
    ) -> anyhow::Result<Self> {
        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![tid_self, tid_other],
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

    pub fn descriptor(
        X_self: &secp256k1::PublicKey,
        X_other: &secp256k1::PublicKey,
    ) -> Result<miniscript::Descriptor<bitcoin::PublicKey>> {
        // Describes the spending policy of the channel fund transaction T_f.
        // For now we use `and(x_self, x_other)` - eventually we might want to replace this with a threshold signature.
        const MINISCRIPT_TEMPLATE: &str = "c:and_v(v:pk(X_self),pk_k(X_other))";

        let X_self = hex::encode(X_self.serialize().to_vec());
        let X_other = hex::encode(X_other.serialize().to_vec());

        let miniscript = MINISCRIPT_TEMPLATE
            .replace("X_self", &X_self)
            .replace("X_other", &X_other);

        let miniscript =
            miniscript::Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str(&miniscript)
                .expect("a valid miniscript");

        Ok(miniscript::Descriptor::Wsh(miniscript))
    }
}

pub struct CommitTransaction {
    inner: Transaction,
}

impl CommitTransaction {
    pub fn new(
        TX_f: &FundingTransaction,
        (X_0, R_0, Y_0): (PublicKey, RevocationPublicKey, PublishingPublicKey),
        (X_1, R_1, Y_1): (PublicKey, RevocationPublicKey, PublishingPublicKey),
        time_lock: u32,
    ) -> Result<Self> {
        let descriptor = Self::descriptor((X_0, R_0, Y_0), (X_1, R_1, Y_1), time_lock)?;

        let input = TX_f.as_txin();
        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input],
            // This output is the same as the input, except for the
            // spending conditions
            output: vec![TxOut {
                value: TX_f.value().as_sat(),
                script_pubkey: descriptor.script_pubkey(),
            }],
        };

        Ok(Self { inner: transaction })
    }

    /// Sign the commit transaction.
    ///
    /// Each party must ensure that they pass the arguments in the
    /// same order that they did when calling
    /// `FundingTransaction::new`.
    pub fn sign(
        self,
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

    pub fn digest(&self, descriptor: miniscript::Descriptor<bitcoin::PublicKey>) -> SigHash {
        let sighash_all = 1;
        self.inner
            .signature_hash(0, &descriptor.witness_script(), sighash_all)
    }

    fn descriptor(
        (X_0, R_0, Y_0): (PublicKey, RevocationPublicKey, PublishingPublicKey),
        (X_1, R_1, Y_1): (PublicKey, RevocationPublicKey, PublishingPublicKey),
        time_lock: u32,
    ) -> Result<miniscript::Descriptor<bitcoin::PublicKey>> {
        let X_0 = hex::encode(X_0.serialize().to_vec());
        let R_0 = hex::encode(Into::<PublicKey>::into(R_0).serialize().to_vec());
        let Y_0 = hex::encode(Into::<PublicKey>::into(Y_0).serialize().to_vec());
        let X_1 = hex::encode(X_1.serialize().to_vec());
        let R_1 = hex::encode(Into::<PublicKey>::into(R_1).serialize().to_vec());
        let Y_1 = hex::encode(Into::<PublicKey>::into(Y_1).serialize().to_vec());

        // Describes the spending policy of the channel commit transaction T_c.
        // There are possible way to spend this transaction:
        // 1. Channel state: It is correctly signed w.r.t pk_0, pk_1 and after relative timelock
        // 2. Punish 0: It is correctly signed w.r.t pk_1, Y_0, R_0
        // 3. Punish 1: It is correctly signed w.r.t pk_0, Y_1, R_1
        // TODO: Make an explicit choice between using `tresh` or composing `or` and `and` (which are both binary operators)
        let channel_state_condition =
            format!("and(older({}),and(pk({}),pk({})))", time_lock, X_0, X_1);
        let punish_0_condition = format!("and(pk({}),and(pk({}),pk({})))", X_1, Y_0, R_0);
        let punish_1_condition = format!("and(pk({}),and(pk({}),pk({})))", X_0, Y_1, R_1);
        let descriptor_str = format!(
            "or({},or({},{}))",
            channel_state_condition, punish_0_condition, punish_1_condition
        );
        let policy = miniscript::policy::Concrete::<bitcoin::PublicKey>::from_str(&descriptor_str)?;
        let miniscript = policy.compile()?;
        let descriptor = miniscript::Descriptor::Wsh(miniscript);

        Ok(descriptor)
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

        let descriptor = SplitTransaction::wpk_descriptor(X_0);
        let output_0 = TxOut {
            value: amount_0.as_sat(),
            script_pubkey: descriptor.script_pubkey(),
        };

        let descriptor = SplitTransaction::wpk_descriptor(X_1);
        let output_1 = TxOut {
            value: amount_1.as_sat(),
            script_pubkey: descriptor.script_pubkey(),
        };

        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input.clone()],
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

    fn wpk_descriptor(key: PublicKey) -> miniscript::Descriptor<bitcoin::PublicKey> {
        let pk = bitcoin::PublicKey {
            key,
            compressed: true,
        };
        miniscript::Descriptor::Wpkh(pk)
    }

    pub fn digest(&self) -> SigHash {
        self.digest
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
        let descriptor = FundingTransaction::descriptor(&X_0, &X_1).unwrap();

        let witness_script = format!("{}", descriptor.witness_script());
        assert_eq!(witness_script, "Script(OP_PUSHBYTES_33 0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166 OP_CHECKSIGVERIFY OP_PUSHBYTES_33 022222222222222222222222222222222222222222222222222222222222222222 OP_CHECKSIG)");
    }

    #[test]
    fn commitment_descriptor_to_witness_script() {
        let X_0 = secp256k1::PublicKey::from_str(
            "032a34617a9141231baa27bcadf622322eed1e16b6036fdf15f42a85f7250c4823",
        )
        .unwrap();
        let R_0 = secp256k1::PublicKey::from_str(
            "03ff65a7fedd9dc637bbaf3cbe4c5971de853e0c359195f19c57211fe0b96ab39e",
        )
        .unwrap()
        .into();
        let Y_0 = secp256k1::PublicKey::from_str(
            "03b3ee07bb851fec17e6cdb2dc235523555dc3193c2ff6399ef28ce941bc57b2b4",
        )
        .unwrap()
        .into();
        let X_1 = secp256k1::PublicKey::from_str(
            "03437a3813f17a264e2c8fc41fb0895634d34c7c9cb9147c553cc67ff37293b1cd",
        )
        .unwrap();
        let R_1 = secp256k1::PublicKey::from_str(
            "02b637ba109a2a844b27d31c9ffac41bfe080d2f0256eeb03839d66442c4ce0deb",
        )
        .unwrap()
        .into();
        let Y_1 = secp256k1::PublicKey::from_str(
            "03851562dd136d68ff0911b4aa6b1ec95850144ddb939a1070159f0a4163d20895",
        )
        .unwrap()
        .into();
        let time_lock = 144;

        let descriptor =
            CommitTransaction::descriptor((X_0, R_0, Y_0), (X_1, R_1, Y_1), time_lock).unwrap();

        let witness_script = format!("{}", descriptor.witness_script());
        assert_eq!(witness_script, "Script(OP_IF OP_PUSHBYTES_33 032a34617a9141231baa27bcadf622322eed1e16b6036fdf15f42a85f7250c4823 OP_CHECKSIGVERIFY OP_PUSHBYTES_33 03437a3813f17a264e2c8fc41fb0895634d34c7c9cb9147c553cc67ff37293b1cd OP_CHECKSIGVERIFY OP_PUSHBYTES_2 9000 OP_CSV OP_ELSE OP_IF OP_DUP OP_HASH160 OP_PUSHBYTES_20 635de934904ad5406559beebcc3ca0d119721323 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 be60bbce0058cb25f268d70559e1a3433d75f557 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 4c8a3449333f92f386b4b8a202353719016261e8 OP_EQUALVERIFY OP_ELSE OP_DUP OP_HASH160 OP_PUSHBYTES_20 1b08ea4a2fbbe0121205f63068f78564ff204995 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 ea92d4bb15b4babd0c216c12f61fe7083ed06e3b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 565dd1650db6ffae1c2dd67d83a5709aa0ddd2e9 OP_EQUALVERIFY OP_ENDIF OP_CHECKSIG OP_ENDIF)");
    }
}
