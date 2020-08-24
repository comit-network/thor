use bitcoin::{consensus::encode, util::psbt::PartiallySignedTransaction};
use serde::{de::Error, Deserialize, Deserializer, Serializer};

pub fn serialize<S>(value: &PartiallySignedTransaction, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let str = encode::serialize_hex(value);
    serializer.serialize_str(&str)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<PartiallySignedTransaction, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let bytes = hex::decode(str).map_err(<D as Deserializer<'de>>::Error::custom)?;

    let value = encode::deserialize(&bytes).map_err(<D as Deserializer<'de>>::Error::custom)?;
    Ok(value)
}
