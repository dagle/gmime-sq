use std::cell::RefCell;

use gio::subclass::prelude::*;
use sequoia_policy_config::ConfiguredStandardPolicy;

pub struct Policy {
    policy: RefCell<ConfiguredStandardPolicy<'static>>,
}

type Result<T, E=anyhow::Error> = std::result::Result<T, E>;

impl Policy {
    pub fn new() -> Self {
        Policy {
            policy: RefCell::new(ConfiguredStandardPolicy::new())
        }
    }
    pub fn parse_config(&self) -> Result<bool> {
        self.policy.borrow_mut().parse_default_config()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
pub struct CryptoPolicyClass {
    pub parent_class: glib::gobject_ffi::GObjectClass,
}

unsafe impl ClassStruct for CryptoPolicyClass {
    type Type = Policy;
}

#[glib::object_subclass]
impl ObjectSubclass for Policy {
    const NAME: &'static str = "CryptoPolicy";
    type Type = super::CryptoPolicy;
    type ParentType = glib::Object;
    type Class = CryptoPolicyClass;
}

impl ObjectImpl for Policy {}

pub(crate) mod ffi {
    use glib::{translate::{IntoGlib, ToGlibPtr}, subclass::types::InstanceStructExt};

    pub type GMimeCryptoPolicy = <super::Policy as super::ObjectSubclass>::Instance;

    #[no_mangle]
    pub unsafe extern "C" fn g_mime_crypto_policy_new() -> *mut GMimeCryptoPolicy {
        let obj = glib::Object::new::<super::super::CryptoPolicy>();
        obj.to_glib_full()
    }

    pub unsafe extern "C" fn g_mime_crypto_policy_parse_config(this: *mut GMimeCryptoPolicy) -> bool {
        let policy = (*this).imp();
        let res = policy.parse_config();
        match res {
            Ok(true) => true,
            Ok(false) => false,
            Err(_) => false,
        }
    }

    #[no_mangle]
    pub extern "C" fn g_mime_sq_context_get_type() -> glib::ffi::GType {
        <super::super::CryptoPolicy as glib::StaticType>::static_type().into_glib()
    }
}
