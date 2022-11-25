use std::cell::RefCell;
use std::convert::TryInto;
use std::io::ErrorKind::WriteZero;
use std::io::{Read, Error, Write};

use glib::subclass::prelude::*;
use gmime::subclass::*;
extern crate sequoia_openpgp as openpgp;
use gmime::traits::StreamExt;
use gmime::StreamExtManual;
use openpgp::policy::StandardPolicy;
use crate::galore_sq_context::sq;

#[derive(Debug)]
pub struct SqContext {
    keyring: RefCell<String>,
}

#[glib::object_subclass]
impl ObjectSubclass for SqContext {
    const NAME: &'static str = "GaloreSqContext";
    type Type = super::SqContext;
    type ParentType = gmime::CryptoContext;
}

impl Default for SqContext {
    fn default() -> Self {
        // Self { keyring: Default::default(), policy: StandardPolicy::new() }
        Self { keyring: Default::default() }
    }
}

struct Stream<'a>(&'a gmime::Stream);

impl<'a> Read for Stream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.0.read(buf);
        if size > 0 {
            Ok(size.try_into().unwrap())
        } else {
            Err(Error::new(WriteZero, "Couldn't read from from stream"))
        }
    }
}

impl<'a> Write for Stream<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let size = self.0.write(buf);
        if size > 0 {
            return Ok(size.try_into().unwrap())
        }
        Err(Error::new(WriteZero, "Couldn't write from from stream"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let size = self.0.flush();
        if size < 0 {
            Err(Error::new(WriteZero, "Couldn't flush stream"))
        } else {
            Ok(())
        }
    }
}

impl ObjectImpl for SqContext {
}

macro_rules! convert_error {
    ($x:expr) => {
       match $x {
           Ok(v) => Ok(v),
           Err(_) => Err(glib::Error::new(glib::FileError::Failed, "Sq Error"))
        } 
    };
}

impl crypto_context::CryptoContextImpl for SqContext {

    fn digest_id(&self, name: &str) -> gmime::DigestAlgo {
        match name {
            "md5" => gmime::DigestAlgo::Md5,
            "sha1" => gmime::DigestAlgo::Sha1,
            "ripemd160" => gmime::DigestAlgo::Ripemd160,
            "md2" => gmime::DigestAlgo::Md2,
            "tiger192" => gmime::DigestAlgo::Tiger192,
            "haval-5-160" => gmime::DigestAlgo::Haval5160,
            "sha256" => gmime::DigestAlgo::Sha256,
            "sha384" => gmime::DigestAlgo::Sha384,
            "sha512" => gmime::DigestAlgo::Sha512,
            "sha224" => gmime::DigestAlgo::Sha224,
            "md4" => gmime::DigestAlgo::Md4,
            _ => gmime::DigestAlgo::Default,
        }
    }

    fn digest_name(&self, digest: gmime::DigestAlgo) -> Option<String> {
        match digest {
            gmime::DigestAlgo::Default => Some("pgp-sha1".to_owned()),
            gmime::DigestAlgo::Md5 => Some("pgp-md5".to_owned()),
            gmime::DigestAlgo::Sha1 => Some("pgp-sha1".to_owned()),
            gmime::DigestAlgo::Ripemd160 => Some("pgp-ripemd160".to_owned()),
            gmime::DigestAlgo::Md2 => Some("pgp-md2".to_owned()),
            gmime::DigestAlgo::Tiger192 => Some("pgp-tiger192".to_owned()),
            gmime::DigestAlgo::Haval5160 => Some("pgp-haval-5-160".to_owned()),
            gmime::DigestAlgo::Sha256 => Some("pgp-sha256".to_owned()),
            gmime::DigestAlgo::Sha384 => Some("pgp-sha384".to_owned()),
            gmime::DigestAlgo::Sha512 => Some("pgp-sha512".to_owned()),
            gmime::DigestAlgo::Sha224 => Some("pgp-sha224".to_owned()),
            gmime::DigestAlgo::Md4 => Some("pgp-md4".to_owned()),
            gmime::DigestAlgo::Crc32 => Some("pgp-sha1".to_owned()),
            gmime::DigestAlgo::Crc32Rfc1510 => Some("pgp-sha1".to_owned()),
            gmime::DigestAlgo::Crc32Rfc2440 => Some("pgp-sha1".to_owned()),
            _ => Some("pgp-sha1".to_owned()),
        }
    }

    fn encryption_protocol(&self) -> Option<String> {
        Some("application/pgp-encrypted".to_owned())
    }

    fn key_exchange_protocol(&self) -> Option<String> {
        Some("application/pgp-keys".to_owned())
    }

    fn signature_protocol(&self) -> Option<String> {
        Some("application/pgp-signature".to_owned())
    }

    fn decrypt(
        &self,
        flags: gmime::DecryptFlags,
        session_key: Option<&str>,
        istream: &gmime::Stream,
        ostream: &gmime::Stream,
    ) -> Result<gmime::DecryptResult, glib::Error> {
        let policy = &StandardPolicy::new(); // flags into policy?
        sq::decrypt(policy, &tsk, recipient, sign, &mut Stream(istream), &mut Stream(ostream))
    }

    fn encrypt(
        &self,
        sign: bool,
        userid: Option<&str>,
        flags: gmime::EncryptFlags,
        recipients: &[&str],
        istream: &gmime::Stream,
        ostream: &gmime::Stream,
    ) -> Result<i32, glib::Error> {
        let policy = &StandardPolicy::new(); // flags into policy?
        sq::encrypt(policy, &tsk, recipient, sign, &mut Stream(istream), &mut Stream(ostream))
    }

    fn sign(
        &self,
        detach: bool,
        userid: &str,
        istream: &gmime::Stream,
        ostream: &gmime::Stream,
    ) -> Result<i32, glib::Error> {
        let tsk = sq::find_cert(userid).unwrap();
        let policy = &StandardPolicy::new();
        sq::sign(policy, detach, &mut Stream(istream), &mut Stream(ostream), &tsk);
    }

    fn verify(
        &self,
        flags: gmime::VerifyFlags,
        istream: &gmime::Stream,
        sigstream: Option<&gmime::Stream>,
        ostream: Option<&gmime::Stream>,
    ) -> Result<Option<gmime::SignatureList>, glib::Error> {
        let policy = &StandardPolicy::new();
        sq::verify()
    }

    fn import_keys(&self, istream: &gmime::Stream) -> Result<i32, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }

    fn export_keys(&self, keys: &[&str], ostream: &gmime::Stream) -> Result<i32, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }
}

pub(crate) mod ffi {
    use gio::subclass::prelude::ObjectSubclassIsExt;
    use glib::translate::*;

    pub type GaloreSqContext = <super::SqContext as super::ObjectSubclass>::Instance;

    #[no_mangle]
    pub unsafe extern "C" fn galore_sq_context_new() -> *mut GaloreSqContext {
        let obj = glib::Object::new::<super::super::SqContext>(&[]);
        let sq = obj.imp();
        sq.keyring.replace("/home/dagle/gmime-sq/testring.pgp".to_owned());
        obj.to_glib_full()
    }

    #[no_mangle]
    pub extern "C" fn galore_sq_context_get_type() -> glib::ffi::GType {
        <super::super::SqContext as glib::StaticType>::static_type().into_glib()
    }
}
