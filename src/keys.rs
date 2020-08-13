use anyhow::{anyhow, bail};
use bitcoin::{hashes::Hash, SigHash};
use conquer_once::Lazy;
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    fun::{
        g,
        marker::{Mark, Normal},
        Point, Scalar, G,
    },
    nonce, Signature, ECDSA,
};
use rand::prelude::ThreadRng;
use sha2::Sha256;
use std::{convert::TryFrom, fmt};

#[derive(Clone)]
pub struct OwnershipKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

#[derive(Clone, PartialEq)]
pub struct OwnershipPublicKey(Point);

impl OwnershipKeyPair {
    pub fn new_random() -> OwnershipKeyPair {
        let (secret_key, public_key) = random_key_pair();

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn public(&self) -> OwnershipPublicKey {
        OwnershipPublicKey(self.public_key.clone())
    }

    pub fn sign(&self, digest: SigHash) -> Signature {
        let ecdsa = ECDSA::new(nonce::from_global_rng::<Sha256, ThreadRng>());

        ecdsa.sign(&self.secret_key, &digest.into_inner())
    }

    pub fn encsign(&self, Y: PublishingPublicKey, digest: SigHash) -> EncryptedSignature {
        let adaptor = Adaptor::<Sha256, _>::new(nonce::from_global_rng::<Sha256, ThreadRng>());

        adaptor.encrypted_sign(&self.secret_key, &Y.0, &digest.into_inner())
    }
}

impl From<Point> for OwnershipPublicKey {
    fn from(public_key: Point) -> Self {
        Self(public_key)
    }
}

impl From<OwnershipPublicKey> for Point {
    fn from(public_key: OwnershipPublicKey) -> Self {
        public_key.0
    }
}

impl From<Scalar> for OwnershipKeyPair {
    fn from(secret_key: Scalar) -> Self {
        let public_key = public_key(&secret_key);

        Self {
            secret_key,
            public_key,
        }
    }
}

#[derive(Clone)]
pub struct RevocationKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

pub struct RevocationSecretKey(Scalar);

#[derive(Clone)]
pub struct RevocationPublicKey(Point);

impl RevocationKeyPair {
    pub fn new_random() -> Self {
        let (secret_key, public_key) = random_key_pair();

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn public(&self) -> RevocationPublicKey {
        RevocationPublicKey(self.public_key.clone())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("revocation secret key does not match revocation public key")]
pub struct WrongRevocationSecretKey;

impl RevocationPublicKey {
    pub fn verify_revocation_secret_key(
        &self,
        secret_key: &RevocationSecretKey,
    ) -> anyhow::Result<()> {
        if self.0 != public_key(&secret_key.0) {
            bail!(WrongRevocationSecretKey)
        }

        Ok(())
    }
}

impl From<Point> for RevocationPublicKey {
    fn from(public_key: Point) -> Self {
        Self(public_key)
    }
}

impl From<RevocationPublicKey> for Point {
    fn from(public_key: RevocationPublicKey) -> Self {
        public_key.0
    }
}

impl From<RevocationKeyPair> for RevocationSecretKey {
    fn from(from: RevocationKeyPair) -> Self {
        RevocationSecretKey(from.secret_key)
    }
}

#[derive(Clone)]
pub struct PublishingKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

#[derive(Clone)]
pub struct PublishingSecretKey(Scalar);

#[derive(Clone)]
pub struct PublishingPublicKey(Point);

impl PublishingKeyPair {
    pub fn new_random() -> Self {
        let (secret_key, public_key) = random_key_pair();

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn public(&self) -> PublishingPublicKey {
        PublishingPublicKey(self.public_key.clone())
    }
}

impl From<Scalar> for PublishingKeyPair {
    fn from(secret_key: Scalar) -> Self {
        let public_key = public_key(&secret_key);

        Self {
            secret_key,
            public_key,
        }
    }
}

impl From<Point> for PublishingPublicKey {
    fn from(public_key: Point) -> Self {
        Self(public_key)
    }
}

impl From<PublishingPublicKey> for Point {
    fn from(public_key: PublishingPublicKey) -> Self {
        public_key.0
    }
}

impl fmt::LowerHex for PublishingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_bytes()))
    }
}

impl fmt::Display for PublishingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_bytes()))
    }
}

impl From<OwnershipPublicKey> for bitcoin::secp256k1::PublicKey {
    fn from(value: OwnershipPublicKey) -> Self {
        value.0.into()
    }
}

impl From<RevocationPublicKey> for bitcoin::secp256k1::PublicKey {
    fn from(value: RevocationPublicKey) -> Self {
        value.0.into()
    }
}

impl From<PublishingPublicKey> for bitcoin::secp256k1::PublicKey {
    fn from(value: PublishingPublicKey) -> Self {
        value.0.into()
    }
}

fn random_key_pair() -> (Scalar, Point) {
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let public_key = public_key(&secret_key);

    (secret_key, public_key)
}

fn public_key(secret_key: &Scalar) -> Point {
    g!(secret_key * G).mark::<Normal>()
}

#[cfg(test)]
pub fn point_from_str(from: &str) -> anyhow::Result<Point> {
    let point = hex::decode(from)?;

    let mut bytes = [0u8; 33];
    bytes.copy_from_slice(point.as_slice());

    let point = Point::from_bytes(bytes).ok_or_else(|| anyhow!("string slice is not a Point"))?;

    Ok(point)
}
