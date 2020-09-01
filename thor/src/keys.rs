use anyhow::bail;
use bitcoin::{hashes::Hash, SigHash};
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature},
    fun::{Point, Scalar},
    nonce::Deterministic,
    Signature, ECDSA,
};
use sha2::Sha256;
use std::fmt;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct OwnershipKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
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
        sign(&self.secret_key, digest)
    }

    pub fn encsign(&self, Y: Point, digest: SigHash) -> EncryptedSignature {
        let adaptor = Adaptor::<Sha256, Deterministic<Sha256>>::default();

        adaptor.encrypted_sign(&self.secret_key, &Y, &digest.into_inner())
    }
}

impl PartialOrd for OwnershipPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0.to_bytes().cmp(&other.0.to_bytes()))
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

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct RevocationKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct RevocationSecretKey(Scalar);

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
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

    pub fn sign(&self, digest: SigHash) -> Signature {
        sign(&self.secret_key, digest)
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

impl From<RevocationSecretKey> for RevocationKeyPair {
    fn from(secret_key: RevocationSecretKey) -> Self {
        let secret_key = secret_key.0;
        let public_key = public_key(&secret_key);

        Self {
            secret_key,
            public_key,
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct PublishingKeyPair {
    secret_key: Scalar,
    public_key: Point,
}

#[derive(Clone, Debug)]
pub struct PublishingSecretKey(Scalar);

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
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

    pub fn sign(&self, digest: SigHash) -> Signature {
        sign(&self.secret_key, digest)
    }
}

impl From<PublishingKeyPair> for PublishingSecretKey {
    fn from(from: PublishingKeyPair) -> Self {
        PublishingSecretKey(from.secret_key)
    }
}

impl From<PublishingKeyPair> for Scalar {
    fn from(from: PublishingKeyPair) -> Self {
        from.secret_key
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

impl From<PublishingSecretKey> for Scalar {
    fn from(secret_key: PublishingSecretKey) -> Self {
        secret_key.0
    }
}

impl From<PublishingPublicKey> for Point {
    fn from(public_key: PublishingPublicKey) -> Self {
        public_key.0
    }
}

impl fmt::LowerHex for PublishingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_bytes()))
    }
}

impl fmt::Display for PublishingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.to_bytes()))
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct PtlcSecret(Scalar);

impl PtlcSecret {
    pub fn new_random() -> Self {
        let secret_key = Scalar::random(&mut rand::thread_rng());

        Self(secret_key)
    }

    pub fn point(&self) -> PtlcPoint {
        PtlcPoint(public_key(&self.0))
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct PtlcPoint(Point);

impl From<PtlcPoint> for Point {
    fn from(from: PtlcPoint) -> Self {
        from.0
    }
}

impl From<PtlcSecret> for Scalar {
    fn from(from: PtlcSecret) -> Self {
        from.0
    }
}

impl From<Scalar> for PtlcSecret {
    fn from(from: Scalar) -> Self {
        Self(from)
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
    let ecdsa = ECDSA::<()>::default();

    ecdsa.verification_key_for(&secret_key)
}

fn sign(secret_key: &Scalar, digest: SigHash) -> Signature {
    let ecdsa = ECDSA::<Deterministic<Sha256>>::default();

    ecdsa.sign(&secret_key, &digest.into_inner())
}

#[cfg(test)]
pub fn point_from_str(from: &str) -> anyhow::Result<Point> {
    let point = hex::decode(from)?;

    let mut bytes = [0u8; 33];
    bytes.copy_from_slice(point.as_slice());

    let point =
        Point::from_bytes(bytes).ok_or_else(|| anyhow::anyhow!("string slice is not a Point"))?;

    Ok(point)
}

#[cfg(feature = "serde")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_public_key_deser_round() {
        let pubkey = OwnershipKeyPair::new_random().public();

        let str = serde_json::to_string(&pubkey).unwrap();
        let res = serde_json::from_str(&str).unwrap();

        assert_eq!(pubkey, res);
    }
}
