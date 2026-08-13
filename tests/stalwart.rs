// NOTE: the shared helpers open sockets through pimalaya-stream, which
// only exists once a TLS provider feature is on.
#![cfg(any(
    feature = "rustls-aws",
    feature = "rustls-ring",
    feature = "native-tls"
))]

mod common;

use crate::common::{Auth, run_smtp};

/// End-to-end test against a local Stalwart SMTP server.
///
/// Start a local Stalwart instance and run with:
///
/// ```sh
/// ./tests/stalwart.sh
/// cargo test --test stalwart -- --ignored
/// ```
///
/// The test uses the default admin credentials and the loopback
/// address.  Stalwart listens on port 25 (SMTP) for submissions by
/// default.
#[test]
#[ignore = "requires a running Stalwart instance on localhost:25 and --ignored"]
fn stalwart() {
    run_smtp("localhost", Auth::None, "test@pimalaya.org");
}
