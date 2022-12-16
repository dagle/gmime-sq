mod imp;
mod sq;
use std::ffi::CString;

use imp::ffi;

use glib::translate::*;

glib::wrapper! {
    pub struct SqContext(ObjectSubclass<imp::SqContext>) @extends gmime::CryptoContext;
}

impl SqContext {
    pub fn new(str: &str) -> Self {
        let cstr = CString::new(str).expect("Couldn't create path");
        unsafe { from_glib_full(ffi::galore_sq_context_new(cstr.as_ptr())) }
    }
}
