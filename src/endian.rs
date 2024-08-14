macro_rules! define_le_to_array {
    ($name: ident, $type: ty, $byte_len: expr) => {
        #[inline]
        pub fn $name(val: $type) -> [u8; $byte_len] {
            debug_assert_eq!(::std::mem::size_of::<$type>(), $byte_len); // size_of isn't a constfn in 1.22
            let mut res = [0; $byte_len];
            for i in 0..$byte_len {
                res[i] = ((val >> i * 8) & 0xff) as u8;
            }
            res
        }
    };
}

define_le_to_array!(u32_to_array_le, u32, 4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endianness_test() {
        assert_eq!(u32_to_array_le(0xdeadbeef), [0xef, 0xbe, 0xad, 0xde]);
    }
}
