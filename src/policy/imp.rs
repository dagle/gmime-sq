use gio::subclass::prelude::*;
use sequoia_policy_config::ConfiguredStandardPolicy;

use crate::error::SqError;

#[repr(C)]
pub struct CryptoPolicyClass {
    pub parent_class: glib::gobject_ffi::GObjectClass,
}

unsafe impl ClassStruct for CryptoPolicyClass {
    type Type = CryptoPolicy;
}

pub struct CryptoPolicy {
    policy: *const libc::c_void,
}

impl Drop for CryptoPolicy {
    fn drop(&mut self) {
        unsafe {
            let pol: &ConfiguredStandardPolicy = std::mem::transmute(self.policy);
            drop(pol);
        }
    }
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self { policy: std::ptr::null() }
    }
}

#[glib::object_subclass]
impl ObjectSubclass for CryptoPolicy {
    const NAME: &'static str = "CryptoPolicy";
    type Type = super::CryptoPolicy;
    type ParentType = glib::Object;
    type Class = CryptoPolicyClass;
}

impl ObjectImpl for CryptoPolicy {
}

impl CryptoPolicy {
    pub fn ptr<'a>(&self) -> Result<&ConfiguredStandardPolicy<'a>, glib::Error> {
        if self.policy.is_null() {
            return Err(glib::Error::new(
                SqError::AutoCryptError, "No data from password handler"));
        }
        unsafe {
            let pol: &ConfiguredStandardPolicy<'a> = std::mem::transmute(self.policy);
            Ok(pol)
        }
    }
}

pub(crate) mod ffi {
    use std::{ffi::CStr, mem::forget};

    use gio::subclass::prelude::ObjectSubclassIsExt;
    use glib::translate::{ToGlibPtr, IntoGlib};
    use sequoia_policy_config::ConfiguredStandardPolicy;

    pub type GMimeCryptoPolicy = <super::CryptoPolicy as super::ObjectSubclass>::Instance;

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_crypto_policy_default()
        -> *mut GMimeCryptoPolicy {
        let obj = glib::Object::new::<super::super::CryptoPolicy>();
        let cp = obj.imp();
        let policy = ConfiguredStandardPolicy::new();
        cp.policy = std::mem::transmute(&policy);
        forget(policy);
        obj.to_glib_full()
        
    }

    pub unsafe extern "C" fn g_mime_crypto_policy_from_file(path: *const libc::c_char)
        -> *mut GMimeCryptoPolicy {
        let obj = glib::Object::new::<super::super::CryptoPolicy>();
        let cp = obj.imp();
        let c_str = CStr::from_ptr(path);
        let mut policy = ConfiguredStandardPolicy::new();
        match c_str.to_str() {
            Ok(s) => {
                policy.parse_config_file(s);
                cp.policy = std::mem::transmute(&policy);
                forget(policy);
                obj.to_glib_full()
            },
            Err(_) => std::ptr::null_mut()
        }
    }

    #[no_mangle]
    pub extern "C" fn g_mime_sq_context_get_type() -> glib::ffi::GType {
        <super::super::CryptoPolicy as glib::StaticType>::static_type().into_glib()
    }
}
