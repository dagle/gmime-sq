mod imp;
use std::ffi::CString;
use imp::ffi;
use glib::translate::*;


glib::wrapper! {
    pub struct CryptoPolicy(ObjectSubclass<imp::CryptoPolicy>);
}

// impl Default for CryptoPolicy {
//     fn default() -> Self {
//         unsafe { from_glib_full(ffi::g_mime_crypto_policy_default()) }
//     }
// }

impl CryptoPolicy {
    pub fn default() -> Self {
        unsafe { from_glib_full(ffi::g_mime_crypto_policy_default()) }
    }
    pub fn from_file(path: &str) -> Self {
        let file = CString::new(path).expect("Couldn't create filepath");
        unsafe { from_glib_full(ffi::g_mime_crypto_policy_from_file(file.as_ptr())) }
    }
}
