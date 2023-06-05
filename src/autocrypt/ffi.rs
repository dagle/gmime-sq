use std::ffi::c_int;

pub type GMimeEncryptionRecommendation = c_int;

pub const GMIME_AUTOCRYPT_RECOMMENDATION_DISABLE: GMimeEncryptionRecommendation = 0;
pub const GMIME_AUTOCRYPT_RECOMMENDATION_DISCOURAGE:  GMimeEncryptionRecommendation = 1;
pub const GMIME_AUTOCRYPT_RECOMMENDATION_AVAILABLE: GMimeEncryptionRecommendation = 2;
pub const GMIME_AUTOCRYPT_RECOMMENDATION_AVAILABLE: GMimeEncryptionRecommendation = 3;

extern "C" {
    pub fn ex_color_get_type() -> glib::ffi::GType;
}
