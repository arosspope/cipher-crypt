//! Contains substitution methods that are used by a variety of ciphers
//!
use super::alphabet;
use super::alphabet::Alphabet;

/// Performs a shift substitution of letters within a piece of text based on the index of them
/// within the alphabet.
///
/// This substitution is defined by the closure `calc_index(ti)`.
/// Where:
///     * ti = the index of the character to shift
///     * note; the closure should the shift value set within
pub fn shift_substitution<F>(text: &str, calc_index: F) -> Result<String, &'static str>
where
    F: Fn(usize) -> usize,
{
    let mut s_text = String::new();
    for c in text.chars() {
        //Find the index of the character in the alphabet (if it exists in there)
        let pos = alphabet::STANDARD.find_position(c);
        match pos {
            Some(pos) => {
                let si = calc_index(pos); //Calculate substitution index

                if let Some(s) = alphabet::STANDARD.get_letter(si, c.is_uppercase()) {
                    s_text.push(s);
                } else {
                    return Err("Calculated an index outside of the known alphabet.");
                }
            }
            None => s_text.push(c), //Push non-alphabetic chars 'as-is'
        }
    }

    Ok(s_text)
}

/// Performs a poly-substitution on a piece of text based on the index of its characters
/// (within the alphabet) and the keystream `k`.
///
/// This substitution is defined by the closure `calc_index(ti, ki)`.
/// Where:
///     * ti = the index of the character to shift
///     * ki = the index of the next key character in the stream
pub fn key_substitution<F>(
    text: &str,
    keystream: &mut Vec<char>,
    calc_index: F,
) -> Result<String, &'static str>
where
    F: Fn(usize, usize) -> usize,
{
    let mut s_text = String::new();

    for tc in text.chars() {
        //Find the index of the character in the alphabet (if it exists in there)
        let tpos = alphabet::STANDARD.find_position(tc);
        match tpos {
            Some(ti) => {
                //Get the next key character in the stream (we always read from position 0)
                if keystream.len() < 1 {
                    return Err("Keystream is not large enough for full substitution of message");
                }

                let kc = keystream[0];
                if let Some(ki) = alphabet::STANDARD.find_position(kc) {
                    //Calculate the index and retrieve the letter to substitute
                    let si = calc_index(ti, ki);
                    if let Some(s) = alphabet::STANDARD.get_letter(si, tc.is_uppercase()) {
                        s_text.push(s);
                    } else {
                        return Err(
                            "Calculated a substitution index outside of the known alphabet.",
                        );
                    }

                    //This character in the keystream has been consumed, shuffle the stream to
                    //the left.
                    keystream.remove(0);
                } else {
                    return Err("Keystream contains a non-alphabetic symbol.");
                }
            }
            None => s_text.push(tc), //Push non-alphabetic chars 'as-is'
        }
    }

    Ok(s_text)
}
