use conquer_once::Lazy;

use anyhow::anyhow;
use bitcoin::{hashes::Hash, SigHash};
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    fun::{
        g,
        hash::Derivation,
        marker::{Mark, Normal},
        Point, Scalar, G,
    },
    Signature, ECDSA,
};
use std::{convert::TryFrom, fmt};

#[derive(Clone)]
pub struct OwnershipKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

#[derive(Clone)]
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
        // TODO: Use a sensible tag
        let ecdsa = ECDSA::from_tag(b"my-tag").enforce_low_s();

        ecdsa.sign(
            &self.secret_key,
            &digest.into_inner(),
            Derivation::Deterministic,
        )
    }

    pub fn presign(&self, Y: PublishingPublicKey, digest: SigHash) -> EncryptedSignature {
        // TODO: Use a sensible tag
        let adaptor = Adaptor::from_tag(b"my-tag");

        adaptor.encrypted_sign(
            &self.secret_key,
            &Y.0,
            &digest.into_inner(),
            Derivation::Deterministic,
        )
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

pub struct RevocationKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

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

impl TryFrom<OwnershipPublicKey> for bitcoin::secp256k1::PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: OwnershipPublicKey) -> anyhow::Result<Self> {
        point_to_bitcoin_pk(value.0)
    }
}

impl TryFrom<RevocationPublicKey> for bitcoin::secp256k1::PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: RevocationPublicKey) -> anyhow::Result<Self> {
        point_to_bitcoin_pk(value.0)
    }
}

impl TryFrom<PublishingPublicKey> for bitcoin::secp256k1::PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: PublishingPublicKey) -> anyhow::Result<Self> {
        point_to_bitcoin_pk(value.0)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("point {0} is not a bitcoin::secp256k1::PublicKey")]
pub struct NotBitcoinPublicKey(Point);

fn point_to_bitcoin_pk(point: Point) -> anyhow::Result<bitcoin::secp256k1::PublicKey> {
    bitcoin::secp256k1::PublicKey::from_slice(&point.to_bytes())
        .map_err(|_| NotBitcoinPublicKey(point).into())
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
