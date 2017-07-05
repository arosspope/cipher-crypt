//! Contains substitution methods that are used by a variety of ciphers
//!
use super::alphabet;

/// Performs a shift substitution of letters within a piece of text based on the index of them
/// within the alphabet.
///
/// This substitution is defined by the closure `calc_index(ti)`.
/// Where:
///     * ti = the index of the character to shift
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

/// Performs a poly-substitution on a piece of text based on the index of its characters
/// (within the alphabet) and the key `k`.
///
/// This substitution is defined by the closure `calc_index(ti, ki)`.
/// Where:
///     * ti = the index of the character to shift
///     * ki = the index of the key character at the nth position of the key/text
pub fn key_substitution<F>(text: &str, key: &str, calc_index: F) -> Result<String, &'static str>
    where F: Fn(usize, usize) -> usize
{
    let mut s_text = String::new();

    for (i, tc) in text.chars().enumerate() {
        //Find the index of the character in the alphabet (if it exists in there)
        let tpos = alphabet::find_position(tc);
        match tpos {
            Some(ti) => {
                //Get the key character at position i
                if let Some(kc) = key.chars().nth(i) {
                    //Get position of character within the alphabet
                    if let Some(ki) = alphabet::find_position(kc) {
                        //Calculate the index and retrieve the letter to substitute
                        let si = calc_index(ti, ki);
                        if let Some(s) = alphabet::get_letter(si, tc.is_uppercase()){
                            s_text.push(s);
                        } else {
                            return Err("Calculated a substitution index outside of the known alphabet.")
                        }
                    } else {
                        return Err("Keystream contains a non-alphabetic symbol.")
                    }
                } else {
                    return Err("Keystream is too small for message length.")
                }

            },
            None => s_text.push(tc), //Push non-alphabetic chars 'as-is'
        }
    }

    Ok(s_text)
}
