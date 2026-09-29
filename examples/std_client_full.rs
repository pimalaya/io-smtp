//! Full std client: pass a URL and an EHLO domain, let
//! [`SmtpClientStd::connect`] open TCP, negotiate TLS, read the
//! greeting, send the initial EHLO, optionally upgrade via STARTTLS,
//! then run the chosen SASL mechanism. It returns the client together
//! with the capability lines of the last EHLO, so no extra round trip
//! is needed to read them. Requires the `rustls-ring` (or `rustls-aws`
//! / `native-tls`) feature.
//!
//! Run with:
//! `URL=smtps://smtp.example.org DOMAIN=client.example.org cargo run --example std_client_full`

use std::{borrow::Cow, env, error::Error};

use io_smtp::{
    client::{SmtpClientStd, SmtpClientStdConnectOptions},
    rfc5321::{SmtpDomain, SmtpEhloDomain},
};
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = Url::parse(&env::var("URL")?)?;
    let domain = env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Owned(domain)));
    let opts = SmtpClientStdConnectOptions::default();

    let (_client, capabilities) = SmtpClientStd::connect(&url, domain, opts)?;

    for capability in capabilities {
        println!("{capability}");
    }

    Ok(())
}
