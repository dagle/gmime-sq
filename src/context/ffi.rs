use std::ffi::{c_char, c_void};
use gmime::CryptoContext;

#[repr(C)]
pub struct GMimeSqContext {
    pub parent: gmime::CryptoContext,
}

#[repr(C)]
pub struct GMimeSqContextClass {
    pub parent: gmime::CryptoContextClass,
}

extern "C" {
    pub fn gmime_sq_context_get_type () -> glib::ffi::GType;
    pub fn gmime_sq_context_new (path: *const c_char) -> *mut GMimeCryptoContext;
}
