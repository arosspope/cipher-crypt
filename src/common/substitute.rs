use super::alphabet::ALPHABET;

pub fn alphabet_substitute<F>(text: &str, calc_index: F) -> String
    where F: Fn(usize) -> usize
{
    let mut s_text = String::new();

    for c in text.chars(){
        //Find the index of the character in the alphabet
        let idx = ALPHABET.iter().position(|&x| x == c);
        match idx {
            Some(i) => {
                let mut si = calc_index(i);

                //If the original character was uppercase we should offset our substitute index
                //by 26 to reference the upper-half (UPPERCASE) section of the alphabet array
                if c.is_uppercase() && si < 26 {
                    si += 26;
                }

                s_text.push(ALPHABET[si]);
            },
            None => s_text.push(c), //Push non-alphabetic chars 'as-is'
        }
    }

    s_text
}
