//! Module to provide the operations required
//! in order to retrieve a ticket from the KDC

mod request_tgt;
mod senders;
pub use request_tgt::{request_as_rep, request_tgt};

mod request_tgs;
pub use request_tgs::{request_regular_tgs, request_s4u2self_tgs, request_tgs};
