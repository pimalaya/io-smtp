#[path = "common.rs"]
mod common;

/// End-to-end test against a local Stalwart SMTP server.
///
/// Start a local Stalwart instance (see `tests/stalwart.sh` in the parent
/// project) and run with:
/// ```sh
/// cargo test --test stalwart -- --ignored
/// ```
///
/// The test uses the default admin credentials and the loopback address.
/// Stalwart listens on port 465 (SMTPS) for submissions by default.
#[test]
#[ignore = "requires a running Stalwart instance on localhost:465"]
fn stalwart_smtp_plain() {
    common::run_smtps(
        "localhost",
        465,
        common::Auth::Plain {
            username: "test@localhost".into(),
            password: "test".into(),
        },
        "test@localhost",
    );
}
