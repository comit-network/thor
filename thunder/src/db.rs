use crate::{channel, ChannelId};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use thor::Channel;

// TODO: Use it
#[allow(dead_code)]
struct Database {
    db: sled::Db,
}

// TODO: Use it
#[allow(dead_code)]
impl Database {
    pub fn new(path: &std::path::Path) -> anyhow::Result<Self> {
        let path = path
            .to_str()
            .ok_or_else(|| anyhow!("The path is not utf-8 valid: {:?}", path))?;
        let db = sled::open(path).context(format!("Could not open the DB at {}", path))?;

        Ok(Database { db })
    }

    pub async fn insert(&self, channel: Channel) -> anyhow::Result<()> {
        let channel_id = channel.channel_id();

        let stored_channel = self.get_channel(&channel_id);

        match stored_channel {
            Ok(_) => Err(anyhow!("Channel is already stored")),
            Err(_) => {
                let key = serialize(&channel_id)?;

                let new_value = serialize(&channel).context("Could not serialize channel")?;

                self.db
                    .compare_and_swap(key, Option::<Vec<u8>>::None, Some(new_value))
                    .context("Could not write in the DB")?
                    .context("Stored channel somehow changed, aborting saving")?;

                self.db
                    .flush_async()
                    .await
                    .map(|_| ())
                    .context("Could not flush db")
            }
        }
    }

    pub fn get_channel(&self, channel_id: &channel::Id) -> anyhow::Result<Channel> {
        let key = serialize(channel_id)?;

        let swap = self
            .db
            .get(&key)?
            .ok_or_else(|| anyhow!("Channel does not exists {}", channel_id))?;

        deserialize(&swap).context("Could not deserialize channel")
    }

    pub fn all(&self) -> anyhow::Result<Vec<Channel>> {
        self.db
            .iter()
            .filter_map(|item| match item {
                Ok((key, value)) => {
                    let channel_id = deserialize::<channel::Id>(&key);
                    let channel =
                        deserialize::<Channel>(&value).context("Could not deserialize channel");

                    match (channel_id, channel) {
                        (Ok(_channel_id), Ok(channel)) => Some(Ok(channel)),
                        (Ok(_), Err(err)) => Some(Err(err)), // If the channel id deserialize,
                        // then it should be a channel
                        (..) => None, // This is not a channel item
                    }
                }
                Err(err) => Some(Err(err).context("Could not retrieve data")),
            })
            .collect()
    }
}

pub fn serialize<T>(t: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize,
{
    Ok(serde_cbor::to_vec(t)?)
}

pub fn deserialize<'a, T>(v: &'a [u8]) -> anyhow::Result<T>
where
    T: Deserialize<'a>,
{
    Ok(serde_cbor::from_slice(v)?)
}
