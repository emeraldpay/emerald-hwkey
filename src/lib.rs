#[macro_use] extern crate log;
extern crate bitcoin;
extern crate sha2;
extern crate ripemd160;
#[cfg(feature = "speculos")]
extern crate serde;
#[cfg(feature = "speculos")] #[macro_use]
extern crate serde_derive;

pub mod errors;
pub mod ledger;