use kerberos_asn1::{
    AsReq, Asn1Object, KerbPaPacRequest, KerberosTime, PaData, PrincipalName,
};
use kerberos_constants::{kdc_options, pa_data_types, principal_names, etypes};
use rand;
use rand::Rng;
use chrono::{Duration, Utc};

pub struct AsReqBuilder {
    realm: String,
    sname: Option<PrincipalName>,
    etypes: Vec<i32>,
    kdc_options: u32,
    cname: Option<PrincipalName>,
    padatas: Vec<PaData>,
    nonce: u32,
    till: KerberosTime,
    rtime: Option<KerberosTime>,
}

impl AsReqBuilder {
    pub fn new(realm: String) -> Self {
        return Self {
            realm: realm.clone(),
            sname: Some(PrincipalName {
                name_type: principal_names::NT_PRINCIPAL,
                name_string: vec!["krbtgt".into(), realm],
            }),
            etypes: supported_etypes(),
            kdc_options: kdc_options::FORWARDABLE
                | kdc_options::RENEWABLE
                | kdc_options::CANONICALIZE
                | kdc_options::RENEWABLE_OK,
            cname: None,
            padatas: Vec::new(),
            nonce: rand::thread_rng().gen(),
            till: Utc::now()
                .checked_add_signed(Duration::weeks(20 * 52))
                .unwrap()
                .into(),
            rtime: Some(
                Utc::now()
                    .checked_add_signed(Duration::weeks(20 * 52))
                    .unwrap()
                    .into(),
            ),
        };
    }

    pub fn cname(mut self, cname: Option<PrincipalName>) -> Self {
        self.cname = cname;
        self
    }

    pub fn username(self, username: String) -> Self {
        self.cname(Some(PrincipalName {
            name_type: principal_names::NT_PRINCIPAL,
            name_string: vec![username],
        }))
    }

    pub fn push_padata(mut self, padata: PaData) -> Self {
        self.padatas.push(padata);
        self
    }

    pub fn request_pac(self) -> Self {
        self.push_padata(PaData::new(
            pa_data_types::PA_PAC_REQUEST,
            KerbPaPacRequest::new(true).build(),
        ))
    }

    pub fn build(self) -> AsReq {
        let mut as_req = AsReq::default();

        as_req.req_body.kdc_options = self.kdc_options.into();
        as_req.req_body.cname = self.cname;
        as_req.req_body.realm = self.realm;
        as_req.req_body.sname = self.sname;
        as_req.req_body.till = self.till;
        as_req.req_body.rtime = self.rtime;
        as_req.req_body.nonce = self.nonce;
        as_req.req_body.etypes = self.etypes;

        if self.padatas.len() > 0 {
            as_req.padata = Some(self.padatas);
        }

        return as_req;
    }
}


fn supported_etypes() -> Vec<i32> {
    vec![
        etypes::RC4_HMAC,
        etypes::AES128_CTS_HMAC_SHA1_96,
        etypes::AES256_CTS_HMAC_SHA1_96,
    ]
}
