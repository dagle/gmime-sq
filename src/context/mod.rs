mod imp;
mod sq;
mod query;
use std::ffi::CString;

use imp::ffi;

use glib::translate::*;

glib::wrapper! {
    pub struct SqContext(ObjectSubclass<imp::SqContext>) @extends gmime::CryptoContext;
}

impl SqContext {
    pub fn new() -> Result<Self, glib::Error> {
        let mut error = std::ptr::null_mut();
        unsafe { 
            let res = from_glib_full(ffi::g_mime_sq_context_new(&mut error));
            if error.is_null() {
                Err(from_glib_full(error))
            } else {
                Ok(res)
            }
        }
    }
    pub fn add_backend(&self, backend: i64, mode: i64) -> Result<(), glib::Error> {
        let mut error = std::ptr::null_mut();
        unsafe { 
            ffi::g_mime_crypto_sq_add_backend(self.to_glib_none().0, backend, mode, &mut error);
            if error.is_null() {
                Err(from_glib_full(error))
            } else {
                Ok(())
            }
        }
    }
    pub fn add_keyserver(&self, url: &str) -> Result<(), glib::Error> {
        let mut error = std::ptr::null_mut();
        unsafe { 
            ffi::g_mime_crypto_sq_add_keyserver(self.to_glib_none().0, url.to_glib_none().0, &mut error);
            if error.is_null() {
                Err(from_glib_full(error))
            } else {
                Ok(())
            }
        }
    }
    // pub new_with_path() -> Self {}
}
