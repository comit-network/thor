pub mod close;
pub mod create;
pub mod punish;
pub mod update;

pub type Result<T> = std::result::Result<T, crate::Error>;
