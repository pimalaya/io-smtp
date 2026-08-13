//! Full std client: pass a URL + TLS config, let
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

use io_sasl::mechanism::Sasl;
use io_smtp::{
    client::SmtpClientStd,
    rfc5321::{SmtpDomain, SmtpEhloDomain},
    session::SmtpSessionOpenOptions,
};
use pimalaya_stream::tls::Tls;
use url::Url;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let url = Url::parse(&env::var("URL")?)?;
    let domain = env::var("DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let domain = SmtpEhloDomain::SmtpDomain(SmtpDomain(Cow::Owned(domain)));
    let tls = Tls::default();
    let opts = SmtpSessionOpenOptions::default();

    let (_client, capabilities) = SmtpClientStd::connect(&url, &tls, domain, None::<Sasl>, opts)?;

    for capability in capabilities {
        println!("{capability}");
    }

    Ok(())
}
