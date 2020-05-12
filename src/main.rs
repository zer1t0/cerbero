mod args;
mod kdc_req_builder;
mod ask_tgs;
mod ask_tgt;
mod senders;
mod utils;
mod krb_cred_plain;
mod cred_format;
mod error;
mod transporter;

use args::{args, ArgumentsParser};
use ask_tgt::ask_tgt;
use ask_tgs::ask_tgs;
use std::net::SocketAddr;
use transporter::new_transporter;

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    let kdc_address = SocketAddr::new(args.kdc_ip, args.kdc_port);
    let transporter = new_transporter(kdc_address, args.transport_protocol);

    if let Some(service) = args.service {
        if let Err(error) = ask_tgs(
            "mickey.ccache",
            service,
            args.username,
            args.realm,
            &*transporter,
        ) {
            eprintln!("{}", error);
        }
    } else {
        if let Err(error) = ask_tgt(args, &*transporter) {
            eprintln!("{}", error);
        }
    }
}
