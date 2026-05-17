#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate alloc;
#[cfg(feature = "client")]
extern crate std;

#[cfg(feature = "client")]
pub mod client;
pub mod login;
pub mod rfc1870;
pub mod rfc3207;
pub mod rfc3461;
pub mod rfc3463;
pub mod rfc4505;
pub mod rfc4616;
pub mod rfc4954;
pub mod rfc5321;
pub mod rfc7628;
#[cfg(feature = "scram")]
pub mod rfc7677;
pub mod send;
pub mod utils;
