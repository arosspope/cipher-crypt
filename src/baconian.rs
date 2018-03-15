//!
//! Write about the cipher here
//!
//!
//!
use std::string::String;
use common::cipher::Cipher;


/// This struct is created by the `new()` method. See its documentation for more.
pub struct Baconian {
    key: String,
}

impl Cipher for Baconian {
    type Key = (String, String, Option<char>);
    type Algorithm = Baconian;
}
