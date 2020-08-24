#![warn(
    unused_extern_crates,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::fallible_impl_from,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::dbg_macro
)]
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

pub use thor::bitcoin;
use thor::Channel;

mod db;

fn main() {
    println!("Hello, world!");
}

pub mod channel {
    use crate::bitcoin::Txid;
    use serde::{Deserialize, Serialize};
    use std::fmt;

    #[derive(Copy, Clone, Debug, Deserialize, Serialize)]
    pub struct Id(Txid);

    impl Id {
        pub fn new(txid: Txid) -> Self {
            Self(txid)
        }
    }

    impl fmt::Display for Id {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:x}", self.0)
        }
    }
}

trait ChannelId {
    fn channel_id(&self) -> channel::Id;
}

impl ChannelId for Channel {
    fn channel_id(&self) -> channel::Id {
        channel::Id::new(self.TX_f_body.inner.txid())
    }
}
