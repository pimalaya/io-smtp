mod common;

use std::env;

use crate::common::{Auth, run_smtps};

/// End-to-end test against the Fastmail SMTP submission service.
///
/// # Example
///
/// ```sh
/// FASTMAIL_EMAIL=test@fastmail.com \
/// FASTMAIL_APP_PASSWORD=xxx \
/// cargo test --test fastmail -- --ignored
/// ```
#[test]
#[ignore = "requires FASTMAIL_{EMAIL,APP_PASSWORD} env vars and --ignored"]
fn fastmail() {
    let email = env::var("FASTMAIL_EMAIL").expect("FASTMAIL_EMAIL not set");
    let password = env::var("FASTMAIL_APP_PASSWORD").expect("FASTMAIL_APP_PASSWORD not set");

    run_smtps(
        "smtp.fastmail.com",
        465,
        Auth::Plain {
            username: email.clone(),
            password,
        },
        &email,
    );
}
