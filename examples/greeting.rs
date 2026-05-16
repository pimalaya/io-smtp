use std::{env, io::Read};

use io_smtp::rfc5321::greeting::*;
use pimalaya_stream::{std::stream::StreamStd, tls::Tls};

fn main() {
    env_logger::init();

    let host = env::var("HOST").expect("HOST env var");
    let port = env::var("PORT")
        .expect("PORT env var")
        .parse()
        .expect("PORT u16");

    let tls = Tls::default();
    let mut stream = StreamStd::connect_tls(&host, port, &tls).unwrap();

    let mut coroutine = GetSmtpGreeting::new();
    let mut arg: Option<&[u8]> = None;
    let mut buf = [0u8; 16 * 1024];

    let greeting = loop {
        match coroutine.resume(arg.take()) {
            GetSmtpGreetingResult::Ok { greeting, .. } => break greeting,
            GetSmtpGreetingResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            GetSmtpGreetingResult::Err(err) => panic!("{err}"),
        }
    };

    println!("greeting: {greeting:#?}");
}
