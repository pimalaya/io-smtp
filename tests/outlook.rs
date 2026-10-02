//! Live end-to-end tests against the Exchange Online (Microsoft 365)
//! submission service; ignored by default, need credentials in the
//! environment.
//!
//! Exchange Online takes STARTTLS on port 587 only, and of the OAuth
//! mechanisms advertises `XOAUTH2` alone. A token minted by hand, with
//! the `https://outlook.office.com/SMTP.Send` scope, goes in
//! `SMTP_MICROSOFT_ACCESS_TOKEN`. Otherwise an app registration trades
//! its client secret for an app-only token through the client
//! credentials grant, so the run needs no human:
//!
//! ```sh
//! SMTP_MICROSOFT_TENANT_ID=… \
//! SMTP_MICROSOFT_CLIENT_ID=… \
//! SMTP_MICROSOFT_CLIENT_SECRET=… \
//! cargo test --test outlook -- --ignored
//! ```
//!
//! The app needs the `SMTP.SendAsApp` application permission of Office
//! 365 Exchange Online, its service principal registered in Exchange
//! with full access to the mailbox, `SMTP_MICROSOFT_USER`
//! (`microsoft@pimalaya.onmicrosoft.com` by default, the Pimalaya test
//! mailbox), and SMTP AUTH enabled on that mailbox.
//!
//! Every run sends one message to the mailbox itself, and it stays in
//! that inbox: deleting it would need Microsoft Graph, which io-smtp
//! does not depend on. Sweep `io-smtp integration test` from time to
//! time, by hand or with an Outlook rule.

// NOTE: the shared helpers open sockets through pimalaya-stream, which
// only exists once a TLS provider feature is on.
#![cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]

mod common;

use std::{borrow::Cow, env};

use bounded_static::IntoBoundedStatic;
use io_oauth::{client::Oauth20ClientStd, rfc6749::client_credentials::*};
use io_sasl::{mechanism::Sasl, xoauth2::SaslXoauth2Creds};
use io_smtp::{
    client::{SmtpClient, SmtpClientStd, SmtpClientStdConnectOptions},
    message::SmtpMessageSendOptions,
    rfc5321::{SmtpDomain, SmtpForwardPath, SmtpLocalPart, SmtpMailbox, SmtpReversePath},
    session::SmtpSessionOpenOptions,
};
use pimalaya_stream::tls::Tls;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::common::run_client;

/// The scope of an app-only Exchange token: every Office 365 Exchange
/// Online application permission the app was granted.
const EXCHANGE_SCOPE: &str = "https://outlook.office365.com/.default";

/// The Pimalaya test mailbox.
const DEFAULT_USER: &str = "microsoft@pimalaya.onmicrosoft.com";

/// End-to-end test of the client layer against the Exchange Online
/// submission service, over STARTTLS, with SASL `XOAUTH2`.
#[test]
#[ignore = "requires SMTP_MICROSOFT_ACCESS_TOKEN or app credentials, and --ignored"]
fn oauth_xoauth2() {
    let user = user();
    let creds = SaslXoauth2Creds {
        username: user.clone(),
        token: token().into(),
    };

    run_client(
        "smtp://smtp.office365.com:587",
        Some(Sasl::Xoauth2(creds)),
        &user,
        true,
    );
}

/// A token Exchange refuses fails the connection cleanly: the server's
/// error challenge is answered and the failure surfaces as the XOAUTH2
/// step's, not as a hang or a protocol error.
#[test]
#[ignore = "requires network access and --ignored"]
fn oauth_xoauth2_rejected() {
    let _ = env_logger::try_init();

    let creds = SaslXoauth2Creds {
        username: user(),
        token: String::from("io-smtp-test-not-a-token").into(),
    };
    let opts = SmtpClientStdConnectOptions {
        sasl: Some(Sasl::Xoauth2(creds)),
        session: SmtpSessionOpenOptions { starttls: true },
        ..Default::default()
    };

    let url = Url::parse("smtp://smtp.office365.com:587").unwrap();
    let domain = SmtpDomain::parse(b"pimalaya.org").unwrap();
    match SmtpClientStd::connect(&url, domain.into(), opts) {
        Ok(_) => panic!("Exchange accepted a forged token"),
        Err(err) => {
            let err = format!("{err:?}");
            assert!(err.contains("Xoauth2"), "not an XOAUTH2 failure: {err}");
        }
    }
}

/// A whole message through `send`, the one-call MAIL FROM, RCPT TO and
/// DATA exchange a mail client uses, its `Bcc:` header stripped on the
/// way.
#[test]
#[ignore = "requires SMTP_MICROSOFT_ACCESS_TOKEN or app credentials, and --ignored"]
fn oauth_message_send() {
    let _ = env_logger::try_init();

    let user = user();
    let creds = SaslXoauth2Creds {
        username: user.clone(),
        token: token().into(),
    };
    let opts = SmtpClientStdConnectOptions {
        sasl: Some(Sasl::Xoauth2(creds)),
        session: SmtpSessionOpenOptions { starttls: true },
        ..Default::default()
    };

    let url = Url::parse("smtp://smtp.office365.com:587").unwrap();
    let domain = SmtpDomain::parse(b"pimalaya.org").unwrap();
    let (mut client, _) = SmtpClientStd::connect(&url, domain.into(), opts).expect("connect");

    let (local, domain) = user.split_once('@').expect("the mailbox is an address");
    let mailbox = SmtpMailbox {
        local_part: SmtpLocalPart(local.to_owned().into()),
        domain: SmtpDomain::parse(domain.as_bytes()).unwrap().into(),
    }
    .into_static();

    let message = [
        &format!("From: io-smtp test <{user}>"),
        &format!("To: io-smtp test <{user}>"),
        &format!("Bcc: io-smtp test <{user}>"),
        "Subject: io-smtp integration test",
        "Date: Thu, 01 Jan 2026 00:00:00 +0000",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "This is an automated test email from io-smtp integration tests.",
        "",
    ]
    .join("\r\n");

    client
        .send(
            SmtpReversePath::SmtpMailbox(mailbox.clone()),
            vec![SmtpForwardPath(mailbox)],
            message.into_bytes(),
            SmtpMessageSendOptions::default(),
        )
        .expect("send");
    client.quit().expect("QUIT");
}

/// The mailbox the tests send as, and to.
fn user() -> String {
    env::var("SMTP_MICROSOFT_USER").unwrap_or_else(|_| String::from(DEFAULT_USER))
}

/// Returns an access token for the run.
///
/// `SMTP_MICROSOFT_ACCESS_TOKEN` short-circuits everything. Otherwise
/// the app's client secret is traded for an app-only token.
fn token() -> String {
    if let Ok(token) = env::var("SMTP_MICROSOFT_ACCESS_TOKEN") {
        return token;
    }

    let var = |name: &str| {
        env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "set SMTP_MICROSOFT_ACCESS_TOKEN, or SMTP_MICROSOFT_TENANT_ID, \
                     SMTP_MICROSOFT_CLIENT_ID and SMTP_MICROSOFT_CLIENT_SECRET to mint one \
                     ({name} is missing)"
                )
            })
    };

    mint_token(
        &var("SMTP_MICROSOFT_TENANT_ID"),
        &var("SMTP_MICROSOFT_CLIENT_ID"),
        var("SMTP_MICROSOFT_CLIENT_SECRET"),
    )
}

/// Trades the app's client secret for an app-only Exchange token (RFC
/// 6749 section 4.4).
fn mint_token(tenant: &str, client_id: &str, secret: String) -> String {
    let token_uri: Url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
        .parse()
        .expect("the token URI is a valid URL");

    let mut client = Oauth20ClientStd::connect(token_uri, &Tls::default(), client_id)
        .expect("connect to the token endpoint");
    client.client_secret = Some(SecretString::from(secret));

    let params = Oauth20ClientCredentialsRequestParams {
        scope: [Cow::from(EXCHANGE_SCOPE)].into_iter().collect(),
    };

    match client
        .request_client_credentials(params)
        .expect("request the client credentials grant")
    {
        Ok(granted) => granted.access_token.expose_secret().to_owned(),
        Err(err) => panic!("the token endpoint refused the client: {err:?}"),
    }
}
