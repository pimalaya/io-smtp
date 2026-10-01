//! Live end-to-end tests against the Gmail SMTP submission service;
//! ignored by default, need credentials in the environment.
//!
//! The app-password test sends as a personal account:
//!
//! ```sh
//! GMAIL_EMAIL=test@gmail.com \
//! GMAIL_APP_PASSWORD=xxx \
//! cargo test --test gmail gmail -- --ignored
//! ```
//!
//! The OAuth tests authenticate with SASL `XOAUTH2` and `OAUTHBEARER`.
//! `SMTP_GOOGLE_ACCESS_TOKEN` takes a token minted by hand, with the
//! `https://mail.google.com/` scope, acting as
//! `SMTP_GOOGLE_SERVICE_ACCOUNT_SUBJECT`. Otherwise a Workspace service
//! account with domain-wide delegation signs its own assertion on
//! behalf of that subject, so the run needs no human:
//!
//! ```sh
//! SMTP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE=key.json \
//! SMTP_GOOGLE_SERVICE_ACCOUNT_SUBJECT=google@pimalaya.org \
//! cargo test --test gmail oauth -- --ignored
//! ```
//!
//! CI passes the key itself rather than a path, as
//! `SMTP_GOOGLE_SERVICE_ACCOUNT_KEY`, since it comes straight out of a
//! secret. The subject defaults to `google@pimalaya.org`, the Pimalaya
//! test user.
//!
//! Every run sends one message to the sender itself, and it stays in
//! that inbox: deleting it would need the Gmail API, which io-smtp does
//! not depend on. Sweep `subject:"io-smtp integration test"` from time
//! to time, by hand or with a Gmail filter.

// NOTE: the shared helpers open sockets through pimalaya-stream, which
// only exists once a TLS provider feature is on.
#![cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]

mod common;

use std::{borrow::Cow, env, fs, time::Duration};

use io_oauth::{
    client::Oauth20ClientStd,
    rfc7523::{
        assertion::{Oauth20JwtBearerClaims, Oauth20JwtBearerKey},
        auth_grant::Oauth20JwtBearerGrantRequestParams,
    },
};
use io_sasl::{
    mechanism::Sasl, rfc7628::oauthbearer::SaslOauthbearerCreds, xoauth2::SaslXoauth2Creds,
};
use pimalaya_stream::tls::Tls;
use secrecy::ExposeSecret;
use serde::Deserialize;
use url::Url;

use crate::common::{Auth, run_client, run_smtps};

const GMAIL_SCOPE: &str = "https://mail.google.com/";
const DEFAULT_SUBJECT: &str = "google@pimalaya.org";

/// End-to-end test against the Gmail SMTP submission service, with an
/// app password.
#[test]
#[ignore = "requires GMAIL_{EMAIL,APP_PASSWORD} env vars and --ignored"]
fn gmail() {
    let email = env::var("GMAIL_EMAIL").expect("GMAIL_EMAIL not set");
    let password = env::var("GMAIL_APP_PASSWORD").expect("GMAIL_APP_PASSWORD not set");

    run_smtps(
        "smtp.gmail.com",
        465,
        Auth::Plain {
            username: email.clone(),
            password,
        },
        &email,
    );
}

/// End-to-end test of the client layer against the Gmail SMTP
/// submission service, over implicit TLS, with SASL `XOAUTH2`.
#[test]
#[ignore = "requires SMTP_GOOGLE_ACCESS_TOKEN or a service account key, and --ignored"]
fn oauth_xoauth2() {
    let subject = subject();
    let creds = SaslXoauth2Creds {
        username: subject.clone(),
        token: token().into(),
    };

    run_client(
        "smtps://smtp.gmail.com:465",
        Some(Sasl::Xoauth2(creds)),
        &subject,
        false,
    );
}

/// End-to-end test of the client layer against the Gmail SMTP
/// submission service, over STARTTLS, with SASL `OAUTHBEARER` (RFC 7628).
#[test]
#[ignore = "requires SMTP_GOOGLE_ACCESS_TOKEN or a service account key, and --ignored"]
fn oauth_oauthbearer() {
    let subject = subject();
    let creds = SaslOauthbearerCreds {
        username: subject.clone(),
        host: String::from("smtp.gmail.com"),
        port: 587,
        token: token().into(),
    };

    run_client(
        "smtp://smtp.gmail.com:587",
        Some(Sasl::Oauthbearer(creds)),
        &subject,
        true,
    );
}

/// The delegated user the tests send as, and to.
fn subject() -> String {
    env::var("SMTP_GOOGLE_SERVICE_ACCOUNT_SUBJECT")
        .unwrap_or_else(|_| String::from(DEFAULT_SUBJECT))
}

/// Returns an access token for the run.
///
/// `SMTP_GOOGLE_ACCESS_TOKEN` short-circuits everything. Otherwise a
/// service account key, held inline in `SMTP_GOOGLE_SERVICE_ACCOUNT_KEY`
/// or at the path `SMTP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE`, is traded for
/// a fresh token acting as the subject.
fn token() -> String {
    if let Ok(token) = env::var("SMTP_GOOGLE_ACCESS_TOKEN") {
        return token;
    }

    if let Ok(key) = env::var("SMTP_GOOGLE_SERVICE_ACCOUNT_KEY") {
        return mint_token(&key);
    }

    if let Ok(path) = env::var("SMTP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE") {
        let key = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("cannot read the service account key at {path}: {err}"));

        return mint_token(&key);
    }

    panic!(
        "set SMTP_GOOGLE_ACCESS_TOKEN, or SMTP_GOOGLE_SERVICE_ACCOUNT_KEY / \
         SMTP_GOOGLE_SERVICE_ACCOUNT_KEY_FILE to mint one"
    );
}

/// The subset of a service account key file the JWT bearer grant needs.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    String::from("https://oauth2.googleapis.com/token")
}

/// Signs a JWT bearer assertion with the service account key, on behalf
/// of the subject, and trades it for an access token (RFC 7523 section
/// 2.1).
///
/// The scopes ride in the claims, which is Google's deviation from the
/// RFC, and io-oauth models it: the token endpoint reads them from there
/// rather than from the request body.
fn mint_token(key: &str) -> String {
    let key: ServiceAccountKey =
        serde_json::from_str(key).expect("the service account key is valid JSON");

    let signer = Oauth20JwtBearerKey::from_pkcs8_pem(&key.private_key)
        .expect("the service account key holds a PKCS#8 private key");

    let token_uri: Url = key.token_uri.parse().expect("the token URI is a valid URL");

    let mut client =
        Oauth20ClientStd::connect(token_uri, &Tls::default(), key.client_email.as_str())
            .expect("connect to the token endpoint");

    let claims = Oauth20JwtBearerClaims {
        iss: key.client_email.as_str().into(),
        sub: Some(subject().into()),
        scope: [Cow::from(GMAIL_SCOPE)].into_iter().collect(),
        ..Default::default()
    };

    // NOTE: iat and exp come from the clock here, in the std client;
    // the coroutine layer underneath stays clock-free.
    let assertion = client
        .sign_jwt_bearer_assertion(&signer, claims, None, Duration::from_secs(600))
        .expect("sign the assertion");

    let params = Oauth20JwtBearerGrantRequestParams {
        assertion,
        scope: Default::default(),
    };

    let response = client
        .request_jwt_bearer_grant(params)
        .expect("trade the assertion for an access token");

    match response {
        Ok(granted) => granted.access_token.expose_secret().to_owned(),
        Err(err) => panic!("the token endpoint refused the assertion: {err:?}"),
    }
}
