#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]
#[macro_use]
extern crate alloc;

pub mod login;
pub mod read;
pub mod rfc3207;
pub mod rfc3461;
pub mod rfc4616;
pub mod rfc4954;
pub mod rfc5321;
pub mod rfc7628;
pub mod rfc7677;
pub mod send;
pub mod utils;
pub mod write;
