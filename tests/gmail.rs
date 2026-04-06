mod common;

use std::env;

use crate::common::{Auth, run_smtps};

/// End-to-end test against the Gmail SMTP submission service.
///
/// # Example
///
/// ```sh
/// GMAIL_EMAIL=test@gmail.com \
/// GMAIL_APP_PASSWORD=xxx \
/// cargo test --test gmail -- --ignored
/// ```
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
