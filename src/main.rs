mod args;
mod as_req_builder;
mod senders;
mod ask_tgt;

use args::{args, ArgumentsParser};
use ask_tgt::ask_tgt;

fn main() {
    let args = ArgumentsParser::parse(&args().get_matches());

    if let Err(error) = ask_tgt(args) {
        eprintln!("{}", error);
    }
}
