//! Contains subsitution methods that are used by a variety of ciphers
//!
use super::alphabet;

/// Performs a shift substitution of letters within a piece of text based on the index of them
/// within the alphabet.
///
/// This substitution is defined by the closure `calc_index`
pub fn shift_substitution<F>(text: &str, calc_index: F) -> Result<String, &'static str>
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
                    return Err("Calculated an index outside of the known alphabet.")
                }
            },
            None => s_text.push(c), //Push non-alphabetic chars 'as-is'
        }
    }

    Ok(s_text)
}
