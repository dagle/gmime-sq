mod imp;
// mod query;
// use std::ffi::CString;

use std::ffi::CString;

use imp::ffi;

use glib::translate::*;
use sequoia_autocrypt_store::peer::Prefer;


glib::wrapper! {
    pub struct AutoCryptStore(ObjectSubclass<imp::AutoCryptStore>);// @extends gmime::CryptoContext;
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
#[non_exhaustive]
pub enum Recommend {
    Disable,
    Discourage,
    Available,
    Encrypt,
    __Unknown(i32),
}

// impl IntoGlib for Recommend {
//     type GlibType;
//
//     fn into_glib(self) -> Self::GlibType {
//         todo!()
//     }
// }

impl AutoCryptStore {
    pub fn new(path: &str, password: &str) -> Self {
        let path = CString::new(path).expect("Couldn't create path");
        let password = CString::new(password).expect("Couldn't create path");
        // unsafe { from_glib_full(ffi::gmime_sq_context_new(cstr.as_ptr())) }

        unsafe { from_glib_full(ffi::g_mime_autocrypt_store_new(path.as_ptr(), password.as_ptr())) }
    }

    pub fn update_private_key(&self, policy: &dyn Policy, account_mail: &str) {
    }

    // TODO: fix date type
    pub fn update_last_seen(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        effective_date: &glib::DateTime,
    ) -> Result<(), glib::Error> {
        Ok(())
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
        Ok(false)
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
    }

    pub fn multi_recommend(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        policy: &CryptoPolicy,
        reply_to_encrypted: bool,
        prefer: gmime::AutocryptPreferEncrypt,
    ) -> gmime::EncryptionRecommendation {
    }

    pub fn header(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        prefer: gmime::AutocryptPreferEncrypt,
    ) -> Result<gmime::AutocryptHeader, glib::Error> {
    }

    pub fn gossip_header(
        &self,
        account_mail: Option<&str>,
        peer_mail: &str,
        policy: &dyn Policy,
    ) -> Result<gmime::AutocryptHeader, glib::Error> {
    }

    pub fn setup_message(&self, account_mail: &str, to: &str) 
        -> Result<(String, gmime::Message), glib::Error> {
    }

    pub fn install_message(
        &self,
        account_mail: &str,
        policy: &dyn Policy,
        message: gmime::Message,
    ) -> Result<(), glib::Error> {
        Ok(())
    }
}
