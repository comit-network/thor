use conquer_once::Lazy;

use bitcoin::{hashes::Hash, SigHash};
use ecdsa_fun::{
    fun::{
        g,
        hash::Derivation,
        marker::{Mark, Normal},
        Point, Scalar, G,
    },
    Signature, ECDSA,
};
use std::fmt;

#[derive(Clone)]
pub struct KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

#[derive(Clone)]
pub struct SecretKey(Scalar);
#[derive(Clone)]
pub struct PublicKey(Point);

impl KeyPair {
    pub fn new_random() -> KeyPair {
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let secret_key = SecretKey(secret_key);

        let public_key = secret_key.public();

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn public(&self) -> PublicKey {
        self.public_key.clone()
    }

    pub fn sign(&self, digest: SigHash) -> Signature {
        // TODO: Use a sensible tag
        let ecdsa = ECDSA::from_tag(b"my-tag").enforce_low_s();

        ecdsa.sign(
            &self.secret_key.0,
            &digest.into_inner(),
            Derivation::Deterministic,
        )
    }
}

impl SecretKey {
    pub fn public(&self) -> PublicKey {
        let sk = &self.0;
        // TODO: Determine what is the correct marker for this public key
        let public_key = g!(sk * G).mark::<Normal>();

        PublicKey(public_key)
    }
}

impl From<SecretKey> for KeyPair {
    fn from(secret_key: SecretKey) -> Self {
        Self {
            secret_key: secret_key.clone(),
            public_key: secret_key.public(),
        }
    }
}

pub struct RevocationKeyPair(KeyPair);
pub struct RevocationPublicKey(PublicKey);

impl RevocationKeyPair {
    pub fn new_random() -> Self {
        let key_pair = KeyPair::new_random();

        Self(key_pair)
    }

    pub fn public(&self) -> RevocationPublicKey {
        RevocationPublicKey(self.0.public_key.clone())
    }
}

impl From<PublicKey> for RevocationPublicKey {
    fn from(public_key: PublicKey) -> Self {
        Self(public_key)
    }
}

impl From<RevocationPublicKey> for PublicKey {
    fn from(r_public_key: RevocationPublicKey) -> Self {
        r_public_key.0
    }
}

pub struct PublishingKeyPair(KeyPair);

#[derive(Clone)]
pub struct PublishingPublicKey(PublicKey);

impl PublishingKeyPair {
    pub fn new_random() -> Self {
        let key_pair = KeyPair::new_random();

        Self(key_pair)
    }

    pub fn public(&self) -> PublishingPublicKey {
        PublishingPublicKey(self.0.public_key.clone())
    }
}

impl From<SecretKey> for PublishingKeyPair {
    fn from(secret_key: SecretKey) -> Self {
        Self(secret_key.into())
    }
}

impl From<PublicKey> for PublishingPublicKey {
    fn from(public_key: PublicKey) -> Self {
        Self(public_key)
    }
}

impl From<PublishingPublicKey> for PublicKey {
    fn from(p_public_key: PublishingPublicKey) -> Self {
        p_public_key.0
    }
}

impl fmt::LowerHex for PublishingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:x}",
            bitcoin::secp256k1::PublicKey::from(self.0.clone())
        )
    }
}

impl fmt::Display for PublishingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:x}",
            bitcoin::secp256k1::PublicKey::from(self.0.clone())
        )
    }
}

impl From<RevocationPublicKey> for bitcoin::secp256k1::PublicKey {
    fn from(_from: RevocationPublicKey) -> Self {
        todo!()
    }
}

impl From<PublishingPublicKey> for bitcoin::secp256k1::PublicKey {
    fn from(_from: PublishingPublicKey) -> Self {
        todo!()
    }
}

impl From<PublicKey> for bitcoin::secp256k1::PublicKey {
    fn from(_from: PublicKey) -> Self {
        todo!()
    }
}
