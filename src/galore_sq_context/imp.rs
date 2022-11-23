use glib::prelude::*;
use glib::subclass::prelude::*;
use gmime::subclass::*;

#[derive(Debug, Default)]
pub struct SqContext {
    name: String
}

#[glib::object_subclass]
impl ObjectSubclass for SqContext {
    const NAME: &'static str = "GaloreSqContext";
    type Type = super::SqContext;
    type ParentType = gmime::CryptoContext;
}

impl ObjectImpl for SqContext {
}

impl crypto_context::CryptoContextImpl for SqContext {
    fn decrypt(
        &self,
        flags: gmime::DecryptFlags,
        session_key: Option<&str>,
        istream: &impl IsA<gmime::Stream>,
        ostream: &impl IsA<gmime::Stream>,
    ) -> Result<gmime::DecryptResult, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }

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

    fn digest_name(&self, digest: gmime::DigestAlgo) -> Option<glib::GString> {
        match digest {
            gmime::DigestAlgo::Default => Some(glib::GString::from("pgp-sha1")),
            gmime::DigestAlgo::Md5 => Some(glib::GString::from("pgp-md5")),
            gmime::DigestAlgo::Sha1 => Some(glib::GString::from("pgp-sha1")),
            gmime::DigestAlgo::Ripemd160 => Some(glib::GString::from("pgp-ripemd160")),
            gmime::DigestAlgo::Md2 => Some(glib::GString::from("pgp-md2")),
            gmime::DigestAlgo::Tiger192 => Some(glib::GString::from("pgp-tiger192")),
            gmime::DigestAlgo::Haval5160 => Some(glib::GString::from("pgp-haval-5-160")),
            gmime::DigestAlgo::Sha256 => Some(glib::GString::from("pgp-sha256")),
            gmime::DigestAlgo::Sha384 => Some(glib::GString::from("pgp-sha384")),
            gmime::DigestAlgo::Sha512 => Some(glib::GString::from("pgp-sha512")),
            gmime::DigestAlgo::Sha224 => Some(glib::GString::from("pgp-sha224")),
            gmime::DigestAlgo::Md4 => Some(glib::GString::from("pgp-md4")),
            gmime::DigestAlgo::Crc32 => Some(glib::GString::from("pgp-sha1")),
            gmime::DigestAlgo::Crc32Rfc1510 => Some(glib::GString::from("pgp-sha1")),
            gmime::DigestAlgo::Crc32Rfc2440 => Some(glib::GString::from("pgp-sha1")),
            _ => Some(glib::GString::from("pgp-sha1")),
        }
    }

    fn encrypt(
        &self,
        sign: bool,
        userid: Option<&str>,
        flags: gmime::EncryptFlags,
        recipients: &[&str],
        istream: &impl IsA<gmime::Stream>,
        ostream: &impl IsA<gmime::Stream>,
    ) -> Result<i32, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }

    fn encryption_protocol(&self) -> Option<String> {
        // Some(glib::GString::from("application/pgp-encrypted"))
        Some("application/pgp-encrypted".to_owned())
    }

    fn key_exchange_protocol(&self) -> Option<glib::GString> {
        Some(glib::GString::from("application/pgp-keys"))
    }

    fn signature_protocol(&self) -> Option<glib::GString> {
        Some(glib::GString::from("application/pgp-signature"))
    }

    fn import_keys(&self, istream: &impl IsA<gmime::Stream>) -> Result<i32, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }

    fn sign(
        &self,
        detach: bool,
        userid: &str,
        istream: &impl IsA<gmime::Stream>,
        ostream: &impl IsA<gmime::Stream>,
    ) -> Result<i32, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }

    fn verify(
        &self,
        flags: gmime::VerifyFlags,
        istream: &impl IsA<gmime::Stream>,
        sigstream: Option<&impl IsA<gmime::Stream>>,
        ostream: Option<&impl IsA<gmime::Stream>>,
    ) -> Result<Option<gmime::SignatureList>, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }

    fn export_keys(&self, keys: &[&str], ostream: &impl IsA<gmime::Stream>) -> Result<i32, glib::Error> {
        let err = glib::Error::new(glib::FileError::Failed, "PGP not support");
        Err(err)
    }
}

pub(crate) mod ffi {
    use glib::translate::*;

    pub type GaloreSqContext = <super::SqContext as super::ObjectSubclass>::Instance;

    #[no_mangle]
    pub unsafe extern "C" fn galore_sq_context_new() -> *mut GaloreSqContext {
        let obj = glib::Object::new::<super::super::SqContext>(&[]);
        obj.to_glib_full()
    }

    #[no_mangle]
    pub extern "C" fn galore_sq_context_get_type() -> glib::ffi::GType {
        <super::super::SqContext as glib::StaticType>::static_type().into_glib()
    }
}
