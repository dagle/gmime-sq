use glib::{Quark, error::ErrorDomain};

#[derive(Clone, Copy)]
pub enum SqError {
    ContextError,
    AutoCryptError,
    PolicyError,
}

impl ErrorDomain for SqError {
    fn domain() -> glib::Quark {
        Quark::from_str("gmime-sq")
    }

    fn code(self) -> i32 {
        match self {
            SqError::ContextError => 1,
            SqError::AutoCryptError => 2,
            SqError::PolicyError => 3,
        }
    }

    fn from(code: i32) -> Option<Self>
    where
        Self: Sized {
            match code {
                1 => Some(SqError::ContextError),
                2 => Some(SqError::AutoCryptError),
                3 => Some(SqError::PolicyError),
                _ => None,
            }
    }
}
