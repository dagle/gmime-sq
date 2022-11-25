mod imp;
mod sq;
use imp::ffi;

use glib::translate::*;

glib::wrapper! {
    pub struct SqContext(ObjectSubclass<imp::SqContext>) @extends gmime::CryptoContext;
}

impl SqContext {
    pub fn new() -> Self {
        unsafe { from_glib_full(ffi::galore_sq_context_new()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use std::cell::RefCell;
    // use std::rc::Rc;

    #[test]
    fn test_new() {
        let sq = SqContext::new();
        drop(sq);
    }

}
