use glib::translate::*;
pub mod imp;
use imp::ffi;

glib::wrapper! {
    pub struct CryptoPolicy(ObjectSubclass<imp::Policy>);
}

impl CryptoPolicy {
    pub fn new() -> Self {
        glib::Object::new()
    }
    pub fn parse_config(&mut self) -> bool {
        unsafe { ffi::g_mime_crypto_policy_parse_config(self.to_glib_none().0) }
    }
}
