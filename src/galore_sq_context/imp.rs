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
    pub keyring: RefCell<String>,
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
        if size >= 0 {
            Ok(size.try_into().unwrap())
        } else {
            Err(Error::new(WriteZero, "Couldn't read from stream"))
        }
    }
}

impl<'a> Write for Stream<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let size = self.0.write(buf);
        if size > 0 {
            return Ok(size.try_into().unwrap())
        }
        Err(Error::new(WriteZero, "Couldn't write from stream"))
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

impl SqContext {
    // fn ask_password(self, userid: &str, prompt: &str, result: gmime::Stream) -> Result<String, glib::Error> {
    fn ask_password(self, userid: &str, prompt: &str, result: gmime::Stream) -> 
        openpgp::Result<String> {

        // let ctx = self.imp();
        // ctx.
        Ok("passw0rd".to_owned())
    }
}

impl ObjectImpl for SqContext {
}

macro_rules! convert_error {
    ($x:expr) => {
       match $x {
           Ok(v) => Ok(v),
           Err(err) => Err(
               glib::Error::new(
                   glib::FileError::Failed, &format!("Sq: {}", err)))
                   // glib::FileError::Failed, "Sq"))
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
        convert_error!(sq::decrypt(self, policy, flags, &mut Stream(istream), &mut Stream(ostream), session_key))
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
        let policy = &StandardPolicy::new();
        convert_error!(sq::encrypt(self, policy, flags, sign, userid, recipients, &mut Stream(istream), &mut Stream(ostream)))
    }

    fn sign(
        &self,
        detach: bool,
        userid: &str,
        istream: &gmime::Stream,
        ostream: &gmime::Stream,
    ) -> Result<i32, glib::Error> {
        let policy = &StandardPolicy::new();
        convert_error!(sq::sign(self, policy, detach, &mut Stream(istream), &mut Stream(ostream), userid))
    }

    fn verify(
        &self,
        flags: gmime::VerifyFlags,
        istream: &gmime::Stream,
        sigstream: Option<&gmime::Stream>,
        ostream: Option<&gmime::Stream>,
    ) -> Result<Option<gmime::SignatureList>, glib::Error> {
        let policy = &StandardPolicy::new();

        let mut sigstream = sigstream.map(|x| Stream(x));
        let sigstream = sigstream.as_mut().map(|x| x as &mut (dyn Read + Sync + Send));
        let mut ostream = ostream.map(|x| Stream(x));
        let ostream = ostream.as_mut().map(|x| x as &mut (dyn Write + Sync + Send));

        convert_error!(sq::verify(self, policy, flags, &mut Stream(istream), sigstream, ostream))
    }

    fn import_keys(&self, istream: &gmime::Stream) -> Result<i32, glib::Error> {
        convert_error!(sq::import_keys(self, &mut Stream(istream)))
    }

    fn export_keys(&self, keys: &[&str], ostream: &gmime::Stream) -> Result<i32, glib::Error> {
        convert_error!(sq::export_keys(self, keys, &mut Stream(ostream)))
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
        // XXX: TODO remove this
        sq.keyring.replace("/home/dagle/code/gmime-sq/key.pgp".to_owned());
        obj.to_glib_full()
    }

    #[no_mangle]
    pub extern "C" fn galore_sq_context_get_type() -> glib::ffi::GType {
        <super::super::SqContext as glib::StaticType>::static_type().into_glib()
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use glib::Cast;

    use crate::galore_sq_context::sq::{sign, verify, encrypt, decrypt, import_keys, export_keys};
    // use tempfile::tempfile;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    static USER: &str = "Testi McTest";

    // #[test]
    // fn test_stream() {
    //     let instream = gmime::StreamMem::with_buffer("this is a string".as_bytes());
    //     let istream = instream.upcast::<gmime::Stream>();
    //     
    //     let mut writer: Vec<u8> = vec![];
    //     
    //     io::copy(&mut Stream(&istream), &mut writer).unwrap();
    //
    //     assert_eq!(writer, b"this is a string" as &[u8]);
    // }

    // Generate a public key
    // and then serialize it
    fn gen_pubkey<'a>() -> &'a [u8] {
        todo!()
    }

    fn gen_tmp_filename() -> String {
        todo!()
    }

    #[test]
    fn test_sign() {
        let policy = &StandardPolicy::new();
        let instream = gmime::StreamMem::with_buffer("this is a string".as_bytes());
        let istream = instream.upcast::<gmime::Stream>();
        let mut output: Vec<u8> = vec![];

        let ctx = super::super::SqContext::new();
        let ctxx = ctx.imp();
        sign(&ctxx, policy, false, &mut Stream(&istream), &mut output, USER).unwrap();
        // gmime::MultipartSigned::sign(ctx, entity, sign, userid, flags, recipients)
    }

    #[test]
    fn test_sign_and_verify() {
        let policy = &StandardPolicy::new();
        let instream = gmime::StreamMem::with_buffer("this is a verify string".as_bytes());
        let istream = instream.upcast::<gmime::Stream>();
        let mut output: Vec<u8> = vec![];
        let mut verifybuf: Vec<u8> = vec![];
        
        let ctx = super::super::SqContext::new();
        let ctxx = ctx.imp();
        sign(&ctxx, policy, false, &mut Stream(&istream), &mut output, USER).unwrap();
        let mut inputoutput: &[u8] = &mut output;
        verify(&ctxx, policy, gmime::VerifyFlags::ENABLE_KEYSERVER_LOOKUPS
            , &mut inputoutput, None, Some(&mut verifybuf)).unwrap();
        // TODO: Check the output from verify
    }

    #[test]
    fn test_encrypt() {
        let policy = &StandardPolicy::new();
        let instream = gmime::StreamMem::with_buffer("this is a string".as_bytes());
        let istream = instream.upcast::<gmime::Stream>();
        let mut output: Vec<u8> = vec![];

        let ctx = super::super::SqContext::new();
        let ctxx = ctx.imp();
        encrypt(ctxx, policy, gmime::EncryptFlags::None, true, Some(USER), 
            &[USER], &mut Stream(&istream), &mut output).unwrap();
    }

    #[test]
    fn test_encrypt_decrypt() {
        let policy = &StandardPolicy::new();
        let instream = gmime::StreamMem::with_buffer("this is decrypt string".as_bytes());
        let istream = instream.upcast::<gmime::Stream>();
        let mut output: Vec<u8> = vec![];
        let mut decryptbuf: Vec<u8> = vec![];

        let ctx = super::super::SqContext::new();
        let ctxx = ctx.imp();
        encrypt(ctxx, policy, gmime::EncryptFlags::None, true, Some(USER), 
            &[USER], &mut Stream(&istream), &mut output).unwrap();
        let mut inputoutput: &[u8] = &mut output;
        decrypt(ctxx, policy, gmime::DecryptFlags::ENABLE_KEYSERVER_LOOKUPS,
            &mut inputoutput, &mut decryptbuf, None).unwrap();
        // TODO: Check the output from decrypt
    }

    #[test]
    fn test_import_keys() {
        let ctx = super::super::SqContext::new();
        let ctxx = ctx.imp();
        // TODO:
        // let file = gen_tmp_filename();
        // ctxx.keyring.replace(file);
        // let mut input = gen_pubkey();
        // import_keys(ctxx, &mut input).unwrap();
    }

    #[test]
    fn test_export_keys() {
        let ctx = super::super::SqContext::new();
        let ctxx = ctx.imp();
        let mut output = vec![];
        export_keys(ctxx, &[USER], &mut output).unwrap();
    }
}
