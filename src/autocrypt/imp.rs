use std::convert::TryInto;
use std::io::ErrorKind::WriteZero;
use std::io::{Read, Error, Write};

use chrono::{DateTime, Utc};
use glib::{Cast, Quark};
use glib::error::ErrorDomain;
use glib::subclass::prelude::*;
extern crate sequoia_openpgp as openpgp;
use gmime::traits::{StreamExt, StreamMemExt, MessageExt, ObjectExt, PartExt, DataWrapperExt, TextPartExt};
use gmime::StreamExtManual;
use openpgp::Cert;
use openpgp::policy::Policy;
use sequoia_autocrypt::AutocryptSetupMessage;
use sequoia_autocrypt_store::peer::Prefer;
use sequoia_autocrypt_store::rusqlite::SqliteDriver;
use sequoia_autocrypt_store::store::AutocryptStore;

use crate::policy::CryptoPolicy;

#[repr(C)]
pub struct AutoCryptStoreClass {
    pub parent_class: glib::gobject_ffi::GObjectClass,
}

unsafe impl ClassStruct for AutoCryptStoreClass {
    type Type = AutoCryptStore;
}

#[derive(Default)]
pub struct AutoCryptStore {
    pub _db: Option<AutocryptStore<SqliteDriver>>,
}

#[glib::object_subclass]
impl ObjectSubclass for AutoCryptStore {
    const NAME: &'static str = "AutocryptStore";
    type Type = super::AutoCryptStore;
    type ParentType = glib::Object;
    type Class = AutoCryptStoreClass;
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
        let size = StreamExtManual::write(self.0, buf);
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

impl ObjectImpl for AutoCryptStore {
}

macro_rules! convert_error {
    ($x:expr) => {
       match $x {
           Ok(v) => Ok(v),
           Err(err) => Err(
               glib::Error::new(
                   AutoCryptError::AutoCryptError, &format!("{}", err)))
        } 
    };
}


pub trait IntoSq<T>: Sized {
    fn into_sq(self) -> T;
}

pub trait FromSq<T>: Sized {
    fn from_sq(value: T) -> Self;
}

impl FromSq<glib::DateTime> for DateTime<Utc> {
    fn from_sq(value: glib::DateTime) -> Self {
        todo!()
    }
}

impl IntoSq<DateTime<Utc>> for glib::DateTime {
    fn into_sq(self) -> DateTime<Utc> {
        todo!()
    }
}

impl IntoSq<Prefer> for gmime::AutocryptPreferEncrypt {
    fn into_sq(self) -> Prefer {
        todo!()
    }
}

// this is kinda bad?
impl IntoSq<Cert> for gmime::Bytes {
    fn into_sq(self) -> Cert {
        todo!()
    }
}

impl IntoSq<gmime::AutocryptHeader> for sequoia_autocrypt::AutocryptHeader {
    fn into_sq(self) -> gmime::AutocryptHeader {
        todo!()
    }
}


// report more than 1 error in the future
#[derive(Clone, Copy)]
enum AutoCryptError {
    AutoCryptError
}

impl ErrorDomain for AutoCryptError {
    fn domain() -> glib::Quark {
        Quark::from_str("gmime-sq")
    }

    fn code(self) -> i32 {
        match self {
            AutoCryptError::AutoCryptError => 0,
        }
    }

    fn from(code: i32) -> Option<Self>
    where
        Self: Sized {
            match code {
                0 => Some(AutoCryptError::AutoCryptError),
                _ => None,
            }
    }
}

pub fn canonicalize(email: &str) -> Result<String, glib::Error> {
    if let Some(email) = sequoia_autocrypt_store::canonicalize(email) {
        Ok(email)
    } else {
        Err(glib::Error::new(
                AutoCryptError::AutoCryptError, "No data from password handler"))
    }
}

impl AutoCryptStore {

    fn db(&self) -> Result<AutocryptStore<SqliteDriver>, glib::Error> {

        self._db.ok_or_else(|| glib::Error::new(AutoCryptError::AutoCryptError, "No connection to db"))
    }

    pub fn update_private_key(&self, policy: &dyn Policy, account_mail: &str) -> Result<(), glib::Error> {
        convert_error!(self.db()?.update_private_key(policy, account_mail))
    }

    pub fn update_last_seen(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        effective_date: &glib::DateTime,
    ) -> Result<(), glib::Error> {
        // convert_error!(self.db()?.update_last_seen(account_mail, peer_mail, effective_date.into_sq()))
        convert_error!(self.db()?.update_last_seen(account_mail, peer_mail, effective_date.into_sq()))
    }

    pub fn update_peer(
        &self,
        account_mail: &str,
        peer_mail: &str,
        key: &glib::Bytes, // a &[u8] or string? or a stream 
        prefer: gmime::AutocryptPreferEncrypt,
        effective_date: &glib::DateTime,
        gossip: bool
    ) -> Result<bool, glib::Error> {
        convert_error!(self.db()?.update_peer(account_mail, peer_mail, &key.into_sq(), 
            prefer.into_sq(), effective_date.into_sq(), gossip))
    }

    pub fn recommend(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        policy: &CryptoPolicy,
        // policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: gmime::AutocryptPreferEncrypt,
    ) -> gmime::EncryptionRecommendation {
        // TODO: Not an error!
        self.db()?.recommend(account_mail, peer_mail, policy, 
            reply_to_encrypted, prefer.into_sq())

    }

    pub fn multi_recommend(
        &self,
        account_mail: Option<&str>,
        peers_mail: &[&str],
        policy: &dyn Policy,
        reply_to_encrypted: bool,
        prefer: gmime::AutocryptPreferEncrypt,
    ) -> gmime::EncryptionRecommendation {
        // TODO: Not an error!
        self.db()?.multi_recommend(account_mail, peers_mail, policy, 
            reply_to_encrypted, prefer.into_sq())
    }

    pub fn header(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        prefer: gmime::AutocryptPreferEncrypt,
    ) -> Result<gmime::AutocryptHeader, glib::Error> {
        let result = convert_error!(self.db()?.header(account_mail, policy, prefer.into_sq()))?;

        Ok(result.into_sq())
    }

    pub fn gossip_header(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        policy: &dyn Policy,
    ) -> Result<gmime::AutocryptHeader, glib::Error> {
        let result = convert_error!(self.db()?.gossip_header(account_mail, peer_mail, policy))?;

        Ok(result.into_sq())
    }

    pub fn setup_message(&self, account_mail: &str, to: &str) 
        -> Result<(String, gmime::Message), glib::Error> {
        let mut setup = convert_error!(self.db()?.setup_message(account_mail))?;

        let mut message = gmime::Message::new(true);

        message.add_mailbox(gmime::AddressType::From, None, account_mail);
        message.add_mailbox(gmime::AddressType::To, None, to);
        message.set_subject("Autocrypt Setup Message", None);

        message.set_header("Autocrypt-Setup-Message", "v1", None);

        let mut mp = gmime::Multipart::new();
        let tp = gmime::TextPart::new();

        tp.set_text(
			"This message contains all information to transfer your Autocrypt\n
			settings along with your secret key securely from your original\n
			device.\n
			\n
			To set up your new device for Autocrypt, please follow the\n
			instuctions that should be presented by your new device.\n
			\n
			You can keep this message and use it as a backup for your secret\n
			key. If you want to do this, you should write down the Setup Code\n
			and store it securely.");

        let mut attach = gmime::Part::with_type("application", "autocrypt-setup");
        attach.set_disposition("attachment");
        attach.set_filename("autocrypt-setup-message.html");
        
        let mem = gmime::StreamMem::new();
        let prefix = 
            "<html><body>\n
            <p>\n
            This is the Autocrypt setup file used to transfer settings and\n
            keys between clients. You can decrypt it using the Setup Code\n
            presented on your old device, and then import the contained key\n
            into your keyring.\n
            </p>\n
            <pre>\n";
        let postfix = "</pre></body></html>";

        mem.write_string(prefix);
        setup.serialize(&mut Stream(&mem.upcast::<gmime::Stream>()));
        mem.write_string(postfix);
        mem.flush();

        let passcode = setup.passcode();
        
        if passcode.is_none() {
            return Err(glib::Error::new(AutoCryptError::AutoCryptError,
                    "Couldn't get a password for setup message"))
        }

        let password: String = passcode.unwrap().map(|p| {
            std::str::from_utf8(&p).unwrap().into()
        });
        
        let dw = gmime::DataWrapper::with_stream(&mem, gmime::ContentEncoding::Default);
        attach.set_content(&dw);

        message.set_mime_part(&mp);
        Ok((password, message))
    }

    pub fn install_message(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        message: gmime::Message,
    ) -> Result<(), glib::Error> {
        message.foreach(|parent, part|
            if let Some(content) = part.content_type_parameter("application") {
                if content == "autocrypt-setup" {
                    return self.install_part(account_mail, policy, part);
                }
            });
        Err(glib::Error::new(AutoCryptError::AutoCryptError,
                "No install part found in message"))
    }

    fn ask_password(&self, userid: &str, prompt: &str, retry: bool) -> 
        Result<String, glib::Error> {
            let mem = gmime::StreamMem::new();
            let stream = mem.clone().upcast::<gmime::Stream>();
            gmime::CryptoContext::request_password(
                userid, prompt, retry
            )?;

            let array = mem.byte_array().ok_or_else(|| glib::Error::new(
                   AutoCryptError::AutoCryptError, "No data from password handler"))?;
            let ret = std::str::from_utf8(array.as_ref())?;
            Ok(ret.to_owned())
    }

    pub fn install_part(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        part: gmime::Part,
    ) -> Result<(), glib::Error> {

        let dw = part.content().ok_or_else(|| glib::Error::new(
                   AutoCryptError::AutoCryptError, "No content"))?;
        let stream = dw.stream().unwrap();

        let mut parser = convert_error!(AutocryptSetupMessage::from_reader(&mut Stream(&stream)))?;

        let prompt = format!(
            "Password for {} of type: {} beginning with: {}",
            account_mail, parser.passcode_format().unwrap_or(""), parser.passcode_begin().unwrap_or("")
            );

        let password = self.ask_password(account_mail, &prompt, false)?;

        // TODO: Have a way to check if password failed etc
        convert_error!(self.db()?.install_message(account_mail, policy, parser, &password.into()))
    }

    pub fn decrypt(
        &self,
        our: &str,
        session_key: Option<&str>,
        policy: &CryptoPolicy,
        istream: &gmime::Stream,
        ostream: &gmime::Stream,
    ) -> Result<gmime::DecryptResult, glib::Error> {

        self.db()?.decrypt(policy.policy, our, &mut Stream(istream), &mut Stream(ostream), session_key)
    }

    pub fn encrypt(
        &self,
        userid: &str,
        recipients: &[&str],
        policy: &CryptoPolicy,
        istream: &gmime::Stream,
        ostream: &gmime::Stream,
    ) -> Result<(), glib::Error> {
        let userid = canonicalize(userid)?;

        let mut recipients_can = vec![];
        for rec in recipients.iter() {
            let canon = canonicalize(rec)?;
            recipients_can.push(canon.as_str());
        }

        convert_error!(self.db()?.encrypt(policy.policy, &userid, &recipients_can,
                &mut Stream(istream), &mut Stream(ostream)))
    }

    // pub fn verify(
    //     &self,
    //     our: &str,
    //     policy: &gmime::Policy,
    //     istream: &gmime::Stream,
    //     sigstream: Option<&gmime::Stream>,
    //     ostream: Option<&gmime::Stream>,
    // ) -> Result<Option<gmime::SignatureList>, glib::Error> {
    //
    //     let mut sigstream = sigstream.map(Stream);
    //     let sigstream = sigstream.as_mut().map(|x| x as &mut (dyn Read + Sync + Send));
    //     let mut ostream = ostream.map(Stream);
    //     let ostream = ostream.as_mut().map(|x| x as &mut (dyn Write + Sync + Send));
    //
    //     convert_error!(self.db()?.verify(policy.policy, Some(our), &mut Stream(istream), sigstream, ostream))
    // }
}


pub(crate) mod ffi {
    use std::ffi::{CStr, CString};

    macro_rules! maybe_str {
        ($acc:expr) => {
            if $acc.is_null() {
                None
            } else {
                let c_account_mail = CStr::from_ptr($acc);
                let account_mail = c_account_mail.to_str().unwrap();
                Some(account_mail)
            }
        };
    }

    use gio::subclass::prelude::{ObjectSubclassIsExt, InstanceStructExt};
    use glib::translate::*;
    use sequoia_autocrypt_store::{rusqlite::SqliteDriver, store::AutocryptStore};

    // pub type Recommend = i32;

    pub type AutoCryptStore = <super::AutoCryptStore as super::ObjectSubclass>::Instance;

    // pub const GMIME_AUTOCRYPT_RECOMMENDATION_DISABLE: i32 =
    //     AutoCryptStore::UIRecommendation::Disable as i32;
    // pub const GMIME_AUTOCRYPT_RECOMMENDATION_DISCOURAGE: i32 =
    //     AutoCryptStore::UIRecommendation::Discourage as i32;
    // pub const GMIME_AUTOCRYPT_RECOMMENDATION_AVAILABLE: i32 =
    //     AutoCryptStore::UIRecommendation::Available as i32;
    // pub const GMIME_AUTOCRYPT_RECOMMENDATION_ENCRYPT: i32 =
    //     AutoCryptStore::UIRecommendation::Encrypt as i32;

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_new(path: *const libc::c_char,
        password: *const libc::c_char)
        -> *mut AutoCryptStore {
        let obj = glib::Object::new::<super::super::AutoCryptStore>();
        let ac = obj.imp();
        // paths can actually be non utf8, we should use OsStr for this
        let c_str = CStr::from_ptr(path);
        match c_str.to_str() {
            Ok(s) => {
                let conn = SqliteDriver::new(s).unwrap();
                // TODO: set password, use None for now
                let store = AutocryptStore::new(conn, None, false).unwrap();
                ac._db = Some(store);
                // ac.keyring.replace(s.to_owned());
                obj.to_glib_full()
            },
            Err(_) => std::ptr::null_mut()
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_update_last_seen(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char,
        peer_mail: *const libc::c_char,
        effective_date: &glib::ffi::GDateTime,
        error: *mut *mut glib::ffi::GError
        ) {
        let imp = (*this).imp();

        // check if account is null
        // account_mail.is_null()
        let account_mail = maybe_str!(account_mail);
        let peer_mail = CStr::from_ptr(peer_mail).to_str().unwrap();
        let ret = imp.update_last_seen(account_mail, peer_mail, effective_date.into_glib());
        match ret {
            Ok(_) => {
                if !error.is_null() {
                    *error = std::ptr::null_mut();
                }
            }
            Err(e) => 
                if !error.is_null() {
                    *error = e.into_glib_ptr();
                }
        }

    }

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_update_peer(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char,
        peer_mail: *const libc::c_char,
        key: &glib::ffi::GBytes,
        prefer: gmime::ffi::GMimeAutocryptPreferEncrypt,
        effective_date: &glib::ffi::GDateTime,
        gossip: bool,
        error: *mut *mut glib::ffi::GError
    ) -> bool {
        let imp = (*this).imp();

        let account_mail = CStr::from_ptr(peer_mail).to_str().unwrap();
        let peer_mail = CStr::from_ptr(peer_mail).to_str().unwrap();

        let ret = imp.update_peer(account_mail, peer_mail, key, prefer, effective_date, gossip);
        match ret {
            Ok(v) => {
                if !error.is_null() {
                    *error = std::ptr::null_mut();
                }
                v
            }
            Err(e) => {
                if !error.is_null() {
                    *error = e.into_glib_ptr();
                }
                false
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_recommend(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char, // can be null
        peer_mail: *const libc::c_char,
        policy: &CryptoPolicy,
        reply_to_encrypted: bool,
        prefer: gmime::ffi::GMimeAutocryptPreferEncrypt,
    ) -> gmime::EncryptionRecommendation  {
        let imp = (*this).imp();

        let account_mail = maybe_str!(account_mail);
        let peer_mail = CStr::from_ptr(peer_mail).to_str();
        imp.recommend(account_mail, peer_mail, policy,
            reply_to_encrypted, prefer.into_sq())
    }

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_get_header(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char,
        policy: &CryptoPolicy,
        prefer: gmime::ffi::GMimeAutocryptPreferEncrypt,
        error: *mut *mut glib::ffi::GError
    ) -> *mut gmime::ffi::GMimeAutocryptHeader {
        let imp = (*this).imp();

        let account_mail = CStr::from_ptr(account_mail).to_str().unwrap();
        let ret = imp.header(account_mail, policy, prefer.into_sq());

        match ret {
            Ok(v) => {
                if !error.is_null() {
                    *error = std::ptr::null_mut();
                }
                v.into_glib_ptr()
            }
            Err(e) => {
                if !error.is_null() {
                    *error = e.into_glib_ptr();
                }
                std::ptr::null_mut()
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_get_gossip_header(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char,
        peer_mail: *const libc::c_char,
        policy: &CryptoPolicy,
        prefer: gmime::ffi::GMimeAutocryptPreferEncrypt,
        error: *mut *mut glib::ffi::GError
    ) -> *mut gmime::ffi::GMimeAutocryptHeader {

        let imp = (*this).imp();
        let account_mail = maybe_str!(account_mail);

        let peer_mail = CStr::from_ptr(peer_mail).to_str().unwrap();
        let ret = imp.gossip_header(account_mail, peer_mail, policy);

        match ret {
            Ok(v) => { 
                if !error.is_null() {
                    *error = std::ptr::null_mut();
                }
                v.into_glib_ptr()
            }
            Err(e) => {
                if !error.is_null() {
                    *error = e.into_glib_ptr();
                }
                std::ptr::null_mut()
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_setup_message(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char,
        from: *const libc::c_char,
        to: *const libc::c_char,
        password: *mut *mut libc::c_char,
        error: *mut *mut glib::ffi::GError
    ) -> *mut gmime::ffi::GMimeMessage {
        let imp = (*this).imp();

        let account_mail = CStr::from_ptr(account_mail).to_str().unwrap();
        let from = CStr::from_ptr(from).to_str().unwrap();
        let to = CStr::from_ptr(to).to_str().unwrap();

        let ret = imp.setup_message(account_mail, from, to);

        match ret {
            Ok((pass, mut mes)) => {
                if !error.is_null() {
                    *error = std::ptr::null_mut();
                }
                let c_str_song = CString::new(pass).unwrap();
                *password = c_str_song.into_raw();
                mes.into_glib_ptr()
            }
            Err(e) => {
                if !error.is_null() {
                    *error = e.into_glib_ptr();
                }
                std::ptr::null_mut()
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_decrypt(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char, // can be null
        session_key: *const libc::c_char, // can be null
        policy: &CryptoPolicy,
        istream: *mut gmime::ffi::GMimeStream,
        ostream: *mut gmime::ffi::GMimeStream,
        error: *mut *mut glib::ffi::GError
    ) {
        let imp = (*this).imp();

        let key = maybe_str!(session_key);

        let account_mail = CStr::from_ptr(account_mail).to_str().unwrap();
        let ret = imp.decrypt(account_mail, session_key, policy, istream, ostream);

        match ret {
            Ok(_) => {
                if !error.is_null() {
                    *error = std::ptr::null_mut();
                }
            }
            Err(e) => {
                if !error.is_null() {
                    *error = e.into_glib_ptr();
                }
            }
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_autocrypt_store_encrypt(
        this: *mut AutoCryptStore,
        account_mail: *const libc::c_char, // can be null
        recipients: &glib::ffi::GPtrArray,
        policy: &CryptoPolicy,
        istream: *mut gmime::ffi::GMimeStream,
        ostream: *mut gmime::ffi::GMimeStream,
        error: *mut *mut glib::ffi::GError
    ) {
        let imp = (*this).imp();

        let num = (*recipients).len as usize;
        let mut recip: Vec<&str> = Vec::with_capacity(num);
        let pdata = (*recipients).pdata;
        for n in 0..num {
            let item_ptr = pdata.add(n);
            let c_str = CStr::from_ptr(*item_ptr as *const libc::c_char);
            recip.push(c_str.to_str().unwrap());
        }

        let account_mail = CStr::from_ptr(account_mail).to_str().unwrap();
        let ret = imp.encrypt(account_mail, &*recip, policy, istream, ostream);

        match ret {
            Ok(_) => {
                if !error.is_null() {
                    *error = std::ptr::null_mut();
                }
            },
            Err(e) => {
                if !error.is_null() {
                    *error = e.into_glib_ptr();
                }
            }
        }
    }


    #[no_mangle]
    pub extern "C" fn gmime_autocrypt_store_get_type() -> glib::ffi::GType {
        <super::super::AutoCryptStore as glib::StaticType>::static_type().into_glib()
    }
}
