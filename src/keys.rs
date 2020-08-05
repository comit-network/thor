use conquer_once::Lazy;

pub use bitcoin::secp256k1::{PublicKey, SecretKey};

pub static SECP: Lazy<bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>> =
    Lazy::new(bitcoin::secp256k1::Secp256k1::new);

// TODO: Consider using libsecp256k1 instead of bitcoin::secp256k1 (or
// even secp256k1FUN!), like we did in A2L. That way we can get rid of
// the `static SECP`, among other things
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

pub struct PublishingKeyPair(KeyPair);
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
