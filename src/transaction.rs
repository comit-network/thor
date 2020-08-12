use crate::{
    keys::{OwnershipKeyPair, OwnershipPublicKey, PublishingPublicKey, RevocationPublicKey},
    ChannelBalance,
};
use anyhow::Context;
use bitcoin::hashes::Hash;
use bitcoin::{
    hashes::hash160, secp256k1, util::bip143::SighashComponents, Amount, OutPoint, Script, SigHash,
    Transaction, TxIn, TxOut,
};
use ecdsa_fun::{self, adaptor::EncryptedSignature, Signature, ECDSA};
use miniscript::{Descriptor, Segwitv0};
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};

#[derive(Clone)]
pub struct FundingTransaction {
    inner: Transaction,
    output_descriptor: miniscript::Descriptor<bitcoin::PublicKey>,
}

// TODO: We assume that the FundingTransaction only has one output,
// but this is probably not true as both parties will likely include
// change outputs
impl FundingTransaction {
    // A `bitcoin::TxIn` does not include the amount, it just
    // references the `previous_output`'s `TxId` and `vout`. There may
    // be a better way of modelling each input than `(TxIn, Amount)`.
    pub fn new(
        (X_a, (tid_a, amount_a)): (OwnershipPublicKey, (TxIn, Amount)),
        (X_b, (tid_b, amount_b)): (OwnershipPublicKey, (TxIn, Amount)),
    ) -> anyhow::Result<Self> {
        let output_descriptor =
            FundingTransaction::build_descriptor(&X_a.try_into()?, &X_b.try_into()?);

        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![tid_a, tid_b],
            output: vec![TxOut {
                value: (amount_a + amount_b).as_sat(),
                script_pubkey: output_descriptor.script_pubkey(),
            }],
        };

        Ok(Self {
            inner: transaction,
            output_descriptor,
        })
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

    pub fn output_descriptor(&self) -> miniscript::Descriptor<bitcoin::PublicKey> {
        self.output_descriptor.clone()
    }

    fn build_descriptor(
        X_a: &secp256k1::PublicKey,
        X_b: &secp256k1::PublicKey,
    ) -> miniscript::Descriptor<bitcoin::PublicKey> {
        // Describes the spending policy of the channel fund transaction T_f.
        // For now we use `and(X_a, X_b)` - eventually we might want to replace this with a threshold signature.
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

#[derive(Clone)]
pub struct CommitTransaction {
    inner: Transaction,
    digest: SigHash,
}

impl CommitTransaction {
    pub fn new(
        TX_f: &FundingTransaction,
        (X_a, R_a, Y_a): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        (X_b, R_b, Y_b): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        time_lock: u32,
    ) -> anyhow::Result<Self> {
        let descriptor = Self::descriptor((X_a, R_a, Y_a), (X_b, R_b, Y_b), time_lock)?;

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

        let digest = Self::compute_digest(&transaction, TX_f);

        Ok(Self {
            inner: transaction,
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

    /// Add signatures to CommitTransaction.
    pub fn add_signatures(
        self,
        (_X_a, _sig_a): (OwnershipPublicKey, Signature),
        (_X_b, _sig_b): (OwnershipPublicKey, Signature),
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

    fn compute_digest(
        commit_transaction: &Transaction,
        funding_transaction: &FundingTransaction,
    ) -> SigHash {
        let input_index = 0;
        let sighash_all = 1;
        commit_transaction.signature_hash(
            input_index,
            &funding_transaction.output_descriptor().witness_script(),
            sighash_all,
        )
    }

    fn descriptor(
        (X_0, R_0, Y_0): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        (X_1, R_1, Y_1): (OwnershipPublicKey, RevocationPublicKey, PublishingPublicKey),
        time_lock: u32,
    ) -> anyhow::Result<Descriptor<bitcoin::PublicKey>> {
        let X_0 = bitcoin::secp256k1::PublicKey::try_from(X_0)?;
        let R_0 = bitcoin::secp256k1::PublicKey::try_from(R_0)?;
        let Y_0 = bitcoin::secp256k1::PublicKey::try_from(Y_0)?;

        let X_1 = bitcoin::secp256k1::PublicKey::try_from(X_1)?;
        let R_1 = bitcoin::secp256k1::PublicKey::try_from(R_1)?;
        let Y_1 = bitcoin::secp256k1::PublicKey::try_from(Y_1)?;

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
        // 1. Channel state: It is correctly signed w.r.t pk_0, pk_1 and after relative timelock
        // 2. Punish 0: It is correctly signed w.r.t pk_1, Y_0, R_0
        // 3. Punish 1: It is correctly signed w.r.t pk_0, Y_1, R_1

        // Policy is or(and(older(144),and(pk(X0),pk(X1))),or(and(pk(X1),and(pk(Y0),pk(R0))),and(pk(X0),and(pk(Y1),pk(R1)))))

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

pub struct SplitTransaction {
    inner: Transaction,
    digest: SigHash,
    balance: ChannelBalance,
}

impl SplitTransaction {
    pub fn new(TX_c: &CommitTransaction, channel_balance: ChannelBalance) -> anyhow::Result<Self> {
        let ChannelBalance {
            a: (amount_a, X_a),
            b: (amount_b, X_b),
        } = channel_balance.clone();

        let input = TX_c.as_txin();

        let descriptor = SplitTransaction::wpk_descriptor(X_a)?;
        let output_a = TxOut {
            value: amount_a.as_sat(),
            script_pubkey: descriptor.script_pubkey(),
        };

        let descriptor = SplitTransaction::wpk_descriptor(X_b)?;
        let output_b = TxOut {
            value: amount_b.as_sat(),
            script_pubkey: descriptor.script_pubkey(),
        };

        let transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![input.clone()],
            output: vec![output_a, output_b],
        };

        let digest = SighashComponents::new(&transaction).sighash_all(
            &input,
            // TODO: May need to instead call `.witness_script()` on the
            // descriptor used to produce the `CommitTransaction`'s output
            // `script_pubkey`
            &input.script_sig,
            TX_c.value().as_sat(),
        );

        Ok(Self {
            inner: transaction,
            digest,
            balance: channel_balance,
        })
    }

    pub fn sign_once(&self, x_self: OwnershipKeyPair) -> Signature {
        x_self.sign(self.digest)
    }

    pub fn balance(&self) -> ChannelBalance {
        self.balance.clone()
    }

    fn wpk_descriptor(
        key: OwnershipPublicKey,
    ) -> anyhow::Result<miniscript::Descriptor<bitcoin::PublicKey>> {
        let pk = bitcoin::PublicKey {
            key: key.try_into()?,
            compressed: true,
        };

        Ok(miniscript::Descriptor::Wpkh(pk))
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
    use crate::keys::point_from_str;
    use ecdsa_fun::fun::Point;
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
        let descriptor = FundingTransaction::build_descriptor(&X_0, &X_1);

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
            CommitTransaction::descriptor((X_0, R_0, Y_0), (X_1, R_1, Y_1), time_lock).unwrap();

        let witness_script = format!("{}", descriptor.witness_script());
        assert_eq!(witness_script, "Script(OP_IF OP_IF OP_DUP OP_HASH160 OP_PUSHBYTES_20 635de934904ad5406559beebcc3ca0d119721323 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 be60bbce0058cb25f268d70559e1a3433d75f557 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 4c8a3449333f92f386b4b8a202353719016261e8 OP_EQUALVERIFY OP_ELSE OP_DUP OP_HASH160 OP_PUSHBYTES_20 1b08ea4a2fbbe0121205f63068f78564ff204995 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 ea92d4bb15b4babd0c216c12f61fe7083ed06e3b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_DUP OP_HASH160 OP_PUSHBYTES_20 565dd1650db6ffae1c2dd67d83a5709aa0ddd2e9 OP_EQUALVERIFY OP_ENDIF OP_ELSE OP_PUSHBYTES_2 9000 OP_CSV OP_VERIFY OP_PUSHBYTES_33 032a34617a9141231baa27bcadf622322eed1e16b6036fdf15f42a85f7250c4823 OP_CHECKSIGVERIFY OP_PUSHBYTES_33 03437a3813f17a264e2c8fc41fb0895634d34c7c9cb9147c553cc67ff37293b1cd OP_ENDIF OP_CHECKSIG)");
    }
}
