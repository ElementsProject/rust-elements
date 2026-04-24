#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let psbt: Result<elements::pset::PartiallySignedTransaction, _> = elements::encode::deserialize(data);
    match psbt {
        Err(_) => {},
        Ok(psbt) => {
            let ser = elements::encode::serialize(&psbt);
            let deser: elements::pset::PartiallySignedTransaction = elements::encode::deserialize(&ser).unwrap();
            // Since the fuzz data could order psbt fields differently, we compare to our deser/ser instead of data
            assert_eq!(ser, elements::encode::serialize(&deser));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00", &mut a);
        super::do_test(&a);
    }
}
