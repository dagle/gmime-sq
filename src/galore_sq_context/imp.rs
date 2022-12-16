use std::cell::RefCell;
use std::convert::TryInto;
use std::io::ErrorKind::WriteZero;
use std::io::{Read, Error, Write};

use glib::Cast;
use glib::subclass::prelude::*;
use glib::translate::{IntoGlib, ToGlibPtr};
use gmime::subclass::*;
extern crate sequoia_openpgp as openpgp;
use gmime::traits::{StreamExt, StreamMemExt};
use gmime::StreamExtManual;
use openpgp::policy::StandardPolicy;
use crate::galore_sq_context::sq;

#[derive(Debug, Default)]
pub struct SqContext {
    pub keyring: RefCell<String>,
}

#[glib::object_subclass]
impl ObjectSubclass for SqContext {
    const NAME: &'static str = "GaloreSqContext";
    type Type = super::SqContext;
    type ParentType = gmime::CryptoContext;
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

unsafe extern "C" fn request_password(ptr: *mut gmime::ffi::GMimeCryptoContext,
    uid: *const libc::c_char,
    prompt: *const libc::c_char,
    retry: glib::ffi::gboolean,
    result: *mut gmime::ffi::GMimeStream,
    err: *mut *mut glib::ffi::GError) -> i32 {
    let fun = (*ptr).request_passwd;
    if let Some(fun) = fun {
        return fun(ptr, uid, prompt, retry, result, err)
    }
    0
}

impl SqContext {
    pub fn ask_password(&self, userid: Option<&str>, prompt: &str, retry: bool) -> 
        openpgp::Result<String> {
        unsafe {
            let self_obj = self.obj();
            let reff = self_obj.clone();
            let ctx = reff.upcast::<gmime::CryptoContext>();
            let mut error = std::ptr::null_mut();
            let mem = gmime::StreamMem::new();
            let stream = mem.clone().upcast::<gmime::Stream>();
            let ret = request_password(
                ctx.to_glib_none().0,
                userid.to_glib_none().0,
                prompt.to_glib_none().0,
                retry.into_glib(),
                stream.to_glib_none().0,
                &mut error
            );

            if ret > 0 {
                let array = mem.byte_array().unwrap();
                let ret = std::str::from_utf8(array.as_ref())?;
                Ok(ret.to_owned())
            } else {
                Err(anyhow::anyhow!("Password request failed"))
            }
        }
    }
}

impl ObjectImpl for SqContext {
}

// TODO: This is reporting the wrong error domain
//
// What we want to do is either to make the error domain
// of gmime introspectable and exported by the gir.
// 
// Or we could create our own error type called 
// gmime_sq_error, then register it (through the gtk-rs auto system or an init function?)
// This would also require us to add these the header file.
//
// The first solution is perfered in that it would be 
// seemless to migrate over, we just map our errors as closely as 
// possible to the gpg and any code matching on that error domain would work
// out of the box. The problem is that our errors might not be excatly the
// same as gpg
// 
// Second solution would allow us to "own" and control our errors.
// Also, I haven't seen any gmime code that matches on the error domains in
// particular.

macro_rules! convert_error {
    ($x:expr) => {
       match $x {
           Ok(v) => Ok(v),
           Err(err) => Err(
               glib::Error::new(
                   // gmime::Error::GENERAL, &format!("{}", err)))
                   glib::FileError::Failed, &format!("Sq: {}", err)))
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

        let mut sigstream = sigstream.map(Stream);
        let sigstream = sigstream.as_mut().map(|x| x as &mut (dyn Read + Sync + Send));
        let mut ostream = ostream.map(Stream);
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
    use std::ffi::CStr;

    use gio::subclass::prelude::ObjectSubclassIsExt;
    use glib::translate::*;

    pub type GaloreSqContext = <super::SqContext as super::ObjectSubclass>::Instance;

    #[no_mangle]
    pub unsafe extern "C" fn galore_sq_context_new(path: *const libc::c_char) -> *mut GaloreSqContext {
        let obj = glib::Object::new::<super::super::SqContext>(&[]);
        let sq = obj.imp();
        let c_str = CStr::from_ptr(path);
        match c_str.to_str() {
            Ok(s) => {
                sq.keyring.replace(s.to_owned());
                obj.to_glib_full()
            },
            Err(_) => std::ptr::null_mut()
        }
    }

    #[no_mangle]
    pub extern "C" fn galore_sq_context_get_type() -> glib::ffi::GType {
        <super::super::SqContext as glib::StaticType>::static_type().into_glib()
    }
}

#[cfg(test)]
// use --test-threads=1 , this is mostly integration tests. 
// If you don't it can fail for 2 reasons:
// 1. Import keys can will truncate db-file before flushing the certs, 
// this will create a race condition.
// 2. glib registering object. Registering the same object twice in the same process
// can crash the test.
mod tests {
    use std::{fs::File, io};

    use glib::Cast;
    use gmime::traits::StreamMemExt;

    use crate::galore_sq_context::sq::{sign, verify, encrypt, decrypt, import_keys, export_keys};

    use super::*;

    static USER: &str = "testi@test.com";

    #[test]
    fn test_stream() {
        let instream = gmime::StreamMem::with_buffer("this is a string".as_bytes());
        let istream = instream.upcast::<gmime::Stream>();
        
        let mut writer: Vec<u8> = vec![];
        
        io::copy(&mut Stream(&istream), &mut writer).unwrap();

        assert_eq!(writer, b"this is a string" as &[u8]);
    }
    #[test]
    fn test_stream_write_and_read() {
        let instream = gmime::StreamMem::new();
        instream.write_string("this is a string");
        instream.flush();

        let array = instream.byte_array().unwrap();
        
        assert_eq!(array.as_ref(), b"this is a string" as &[u8]);
    }


    #[test]
    fn test_sign() {
        let policy = &StandardPolicy::new();
        let instream = gmime::StreamMem::with_buffer("this is a string".as_bytes());
        let istream = instream.upcast::<gmime::Stream>();
        let mut output: Vec<u8> = vec![];

        let ctx = super::super::SqContext::new("/home/dagle/code/gmime-sq/testring.pgp");
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
        
        let ctx = super::super::SqContext::new("/home/dagle/code/gmime-sq/testring.pgp");
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

        let ctx = super::super::SqContext::new("/home/dagle/code/gmime-sq/testring.pgp");
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

        let ctx = super::super::SqContext::new("/home/dagle/code/gmime-sq/testring.pgp");
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
        let ctx = super::super::SqContext::new("/home/dagle/code/gmime-sq/testring.pgp");
        let ctxx = ctx.imp();
        let mut file = File::open("/home/dagle/code/gmime-sq/import-keys.pgp").unwrap();
        let num = import_keys(ctxx, &mut file).unwrap();
        assert_eq!(num, 1);
    }

    #[test]
    fn test_export_keys() {
        let ctx = super::super::SqContext::new("/home/dagle/code/gmime-sq/testring.pgp");
        let ctxx = ctx.imp();
        let mut output = vec![];
        let num = export_keys(ctxx, &[USER], &mut output).unwrap();
        let str = String::from_utf8(output).unwrap();
        println!("Keys: {}", &str);
        assert_eq!(num, 1);
    }
}
