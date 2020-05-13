mod args;
mod ask_tgs;
mod ask_tgt;
mod cred_format;
mod error;
mod kdc_req_builder;
mod krb_cred_plain;
mod senders;
mod transporter;
mod utils;

use crate::error::Result;
use args::{args, Arguments, ArgumentsParser};
use ask_tgs::ask_tgs;
use ask_tgt::ask_tgt;
use std::net::SocketAddr;
use transporter::new_transporter;
use utils::resolve_host;

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    if let Err(error) = main_inner(args) {
        eprintln!("{}", error);
    }
}

fn main_inner(args: Arguments) -> Result<()> {

    let kdc_ip = match args.kdc_ip {
        Some(ip) => ip,
        None => resolve_host(&args.realm)?
    };


    let kdc_address = SocketAddr::new(kdc_ip, args.kdc_port);
    let transporter = new_transporter(kdc_address, args.transport_protocol);

    if let Some(service) = args.service {
        return ask_tgs(
            "mickey.ccache",
            service,
            args.username,
            args.realm,
            &*transporter,
        );
    } else {
        return ask_tgt(
            &args.realm,
            &args.username,
            &args.user_key,
            args.preauth,
            &*transporter,
            &args.ticket_format,
            &args.out_file,
        );
    }
}
