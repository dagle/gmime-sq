extern crate sequoia_openpgp as openpgp;
use std::{time::SystemTime, borrow::Borrow};


use openpgp::{cert::{Cert, prelude::ValidKeyAmalgamation}, policy::Policy, packet::{UserID, key::{UnspecifiedRole, PublicParts}}, types::KeyFlags};
use sequoia_openpgp::KeyHandle;

pub enum Query<'a> {
    ExactKey(KeyHandle),
    Key(KeyHandle),
    ExactEmail(String),
    Email(memchr::memmem::Finder<'a>),
    ExactUID(UserID),
    Substring(memchr::memmem::Finder<'a>),
}

impl<'a> From<&'a str> for Query<'a> {
    fn from(s: &str) -> Query {
        if s.ends_with("!") {
            if let Ok(h) = s[..s.len()-1].parse() {
                return Query::ExactKey(h);
            }
        }

        if let Ok(h) = s.parse() {
            Query::Key(h)

        } else if s.starts_with("=") {
            Query::ExactUID(s[1..].into())
        } else if s.starts_with("<") && s.ends_with(">") {
            Query::ExactEmail(s[1..s.len()-1].into())
        } else if s.starts_with("@") {
            Query::Email(memchr::memmem::Finder::new(&s[1..]))
        } else {
            Query::Substring(memchr::memmem::Finder::new(s))
        }
    }
}

fn get_keys_handle<'a, C>(certs: &'a [C], policy: &'a dyn Policy, ts: Option<SystemTime>, h: &KeyHandle, flags: &KeyFlags) -> Vec<ValidKeyAmalgamation<'a, PublicParts, UnspecifiedRole, bool>>
    where C: Borrow<Cert> {

    let mut keys = vec![];
    for c in certs {
        let cert: &Cert = c.borrow();

        for ka in cert.keys().with_policy(policy, ts).alive()
            .revoked(false).key_flags(flags).supported() {
            if ka.key_handle().aliases(h) {
                keys.push(ka);
            }
        }
    }
    keys
}

fn get_keys_exact_handle<'a, C>(certs: &'a [C], policy: &'a dyn Policy, ts: Option<SystemTime>, h: &KeyHandle, flags: &KeyFlags) -> Vec<ValidKeyAmalgamation<'a, PublicParts, UnspecifiedRole, bool>>
    where C: Borrow<Cert> {

    let mut keys = vec![];
    for c in certs {
        let cert: &Cert = c.borrow();

        for ka in cert.keys().with_policy(policy, ts).alive()
            .revoked(false).key_flags(flags).supported() {
            if ka.key_handle() == *h {
                keys.push(ka);
            }
        }
    }
    keys
}

impl Query<'_> {
    pub fn matches(&self, cert: &Cert) -> bool {
        match self {
            Query::ExactKey(h) => 
                cert.keys().any(|k| k.key_handle() == *h),
            Query::Key(h) =>
                cert.keys().any(|k| k.key_handle().aliases(h)),
            Query::ExactEmail(e) => 
                cert.userids().any(|u| u.email().ok().flatten().as_ref() == Some(e)),
            Query::Email(f) => {
                cert.userids().any(|u| {
                    match u.email() {
                        Ok(Some(s)) => f.find(s.as_bytes()).is_some(),
                        _ => false,
                    }
                })
            }
            Query::ExactUID(u) =>
                cert.userids().any(|cu| cu.userid() == u),
            Query::Substring(f) =>
                cert.userids().any(|u| f.find(u.value()).is_some()),
        }
    }

    pub fn get_cert<'a>(&self, certs: &'a [Cert]) -> Option<&'a Cert> {
        certs.iter().find(|x| self.matches(x))
    }

    fn get_keys_filltered<'a, C>(&self, certs: &'a [C], policy: &'a dyn Policy, ts: Option<SystemTime>, flags: &KeyFlags) -> Vec<ValidKeyAmalgamation<'a, PublicParts, UnspecifiedRole, bool>>
        where C: Borrow<Cert> {

            let mut keys = vec![];
            for c in certs {
                let cert: &Cert = c.borrow();

                if self.matches(cert) {
                    for ka in cert.keys().with_policy(policy, ts).alive()
                        .revoked(false).key_flags(flags).supported() {
                            keys.push(ka);
                    }
            }
        }
        keys
    }
    pub fn get_signing_keys<'a, C>(&self, certs: &'a [C], p: &'a dyn Policy, ts: Option<SystemTime>) -> Vec<ValidKeyAmalgamation<'a, PublicParts, UnspecifiedRole, bool>>
        where C: Borrow<Cert> {
        let flags = &KeyFlags::empty().set_signing();
        match self {
            Query::ExactKey(h) => 
                get_keys_exact_handle(certs, p, ts, h, flags),
            Query::Key(h) => 
                get_keys_handle(certs, p, ts, h, flags),
            _ => 
                self.get_keys_filltered(certs, p, ts, flags)
        }
    }
}
