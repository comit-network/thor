use conquer_once::Lazy;

pub use bitcoin::secp256k1::{PublicKey, SecretKey};
use std::fmt;

pub static SECP: Lazy<bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>> =
    Lazy::new(bitcoin::secp256k1::Secp256k1::new);

// TODO: Consider using libsecp256k1 instead of bitcoin::secp256k1 (or
// even secp256k1FUN!), like we did in A2L. That way we can get rid of
// the `static SECP`, among other things
#[derive(Clone)]
pub struct KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl KeyPair {
    pub fn new_random() -> KeyPair {
        let (secret_key, public_key) =
            SECP.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn public(&self) -> PublicKey {
        self.public_key
    }
}

impl From<SecretKey> for KeyPair {
    fn from(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            public_key: PublicKey::from_secret_key(&SECP, &secret_key),
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
        RevocationPublicKey(self.0.public_key)
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

#[derive(Clone, Copy)]
pub struct PublishingPublicKey(PublicKey);

impl PublishingKeyPair {
    pub fn new_random() -> Self {
        let key_pair = KeyPair::new_random();

        Self(key_pair)
    }

    pub fn public(&self) -> PublishingPublicKey {
        PublishingPublicKey(self.0.public_key)
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
        write!(f, "{:x}", self.0)
    }
}

impl fmt::Display for PublishingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
