//! Contains subsitution methods that are used by a variety of ciphers
//!
use super::alphabet;

/// Performs a mono substitution on a piece of text based on the index of its characters
/// within the alphabet.
///
/// This substitution is defined by the closure `calc_index`
pub fn mono_substitution<F>(text: &str, calc_index: F) -> String
    where F: Fn(usize) -> usize
{
    let mut s_text = String::new();
    for c in text.chars(){
        //Find the index of the character in the alphabet (if it exists in there)
        let pos = alphabet::find_position(c);
        match pos {
            Some(pos) => {
                let si = calc_index(pos); //Calculate substitution index

                if let Some(s) = alphabet::get_letter(si, c.is_uppercase()) {
                    s_text.push(s);
                } else {
                    //Something has gone wrong with indexing, just push char 'as-is'
                    s_text.push(c);
                }
            },
            None => s_text.push(c), //Push non-alphabetic chars 'as-is'
        }
    }

    s_text
}
