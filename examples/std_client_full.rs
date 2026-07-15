//! Full std client: pass a URL + TLS config, let
//! [`SmtpClientStd::connect`] open TCP, negotiate TLS, read the
//! greeting, send the initial EHLO, optionally upgrade via STARTTLS,
//! then run the chosen SASL mechanism. Requires the `rustls-ring`
//! (or `rustls-aws` / `native-tls`) feature.
//!
//! Run with:
//! `URL=smtps://smtp.example.org DOMAIN=client.example.org cargo run --example std_client_full`

use std::{borrow::Cow, env, error::Error};

use io_smtp::{
    client::SmtpClientStd,
    rfc5321::types::{domain::SmtpDomain, ehlo_domain::SmtpEhloDomain},
};
use pimalaya_stream::{sasl::Sasl, tls::Tls};
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = Url::parse(&env::var("URL")?)?;
    let domain = env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Owned(domain)));
    let tls = Tls::default();

    let mut client = SmtpClientStd::connect(&url, &tls, false, domain.clone(), None::<Sasl>)?;
    let capabilities = client.ehlo(domain)?;

    for capability in capabilities {
        println!("{capability}");
    }

    Ok(())
}
