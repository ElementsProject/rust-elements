use std::io;

use crate::encode;

/// Extensions of `Write` to encode data as per Bitcoin consensus.
pub trait WriteExt: io::Write {
    /// Outputs a 64-bit unsigned integer.
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Outputs a 32-bit unsigned integer.
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Outputs a 16-bit unsigned integer.
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Outputs an 8-bit unsigned integer.
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Outputs a 64-bit signed integer.
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Outputs a 32-bit signed integer.
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Outputs a 16-bit signed integer.
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Outputs an 8-bit signed integer.
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Outputs a variable sized integer.
    fn emit_varint(&mut self, v: u64) -> Result<usize, io::Error>;

    /// Outputs a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Outputs a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<usize, io::Error>;
}

/// Extensions of `Read` to decode data as per Bitcoin consensus.
pub trait ReadExt: io::Read {
    /// Reads a 64-bit unsigned integer.
    fn read_u64(&mut self) -> Result<u64, encode::Error>;
    /// Reads a 32-bit unsigned integer.
    fn read_u32(&mut self) -> Result<u32, encode::Error>;
    /// Reads a 16-bit unsigned integer.
    fn read_u16(&mut self) -> Result<u16, encode::Error>;
    /// Reads an 8-bit unsigned integer.
    fn read_u8(&mut self) -> Result<u8, encode::Error>;

    /// Reads a 64-bit signed integer.
    fn read_i64(&mut self) -> Result<i64, encode::Error>;
    /// Reads a 32-bit signed integer.
    fn read_i32(&mut self) -> Result<i32, encode::Error>;
    /// Reads a 16-bit signed integer.
    fn read_i16(&mut self) -> Result<i16, encode::Error>;
    /// Reads an 8-bit signed integer.
    fn read_i8(&mut self) -> Result<i8, encode::Error>;

    /// Reads a variable sized integer.
    fn read_varint(&mut self) -> Result<u64, encode::Error>;

    /// Reads a boolean.
    fn read_bool(&mut self) -> Result<bool, encode::Error>;

    /// Reads a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), encode::Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> core::result::Result<(), io::Error> {
            self.write_all(&v.to_le_bytes())
        }
    };
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> core::result::Result<$val_type, encode::Error> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(encode::Error::Io)?;
            Ok(<$val_type>::from_le_bytes(val))
        }
    };
}

impl<W: io::Write + ?Sized> WriteExt for W {
    encoder_fn!(emit_u64, u64);
    encoder_fn!(emit_u32, u32);
    encoder_fn!(emit_u16, u16);
    encoder_fn!(emit_i64, i64);
    encoder_fn!(emit_i32, i32);
    encoder_fn!(emit_i16, i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> {
        self.write_all(&[v])
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<usize, io::Error> {
        self.write_all(v)?;
        Ok(v.len())
    }
    #[inline]
    fn emit_varint(&mut self, v: u64) -> Result<usize, io::Error> {
        match v {
            i @ 0..=0xFC => {
                self.emit_u8(i as u8)?;
                Ok(1)
            }
            i @ 0xFD..=0xFFFF => {
                self.emit_u8(0xFD)?;
                self.emit_u16(i as u16)?;
                Ok(3)
            }
            i @ 0x10000..=0xFFFFFFFF => {
                self.emit_u8(0xFE)?;
                self.emit_u32(i as u32)?;
                Ok(5)
            }
            i => {
                self.emit_u8(0xFF)?;
                self.emit_u64(i)?;
                Ok(9)
            }
        }
    }
}

impl<R: io::Read + ?Sized> ReadExt for R {
    decoder_fn!(read_u64, u64, 8);
    decoder_fn!(read_u32, u32, 4);
    decoder_fn!(read_u16, u16, 2);
    decoder_fn!(read_i64, i64, 8);
    decoder_fn!(read_i32, i32, 4);
    decoder_fn!(read_i16, i16, 2);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, encode::Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0])
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, encode::Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0] as i8)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, encode::Error> {
        ReadExt::read_i8(self).map(|bit| bit != 0)
    }
    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), encode::Error> {
        self.read_exact(slice).map_err(encode::Error::Io)
    }
    #[inline]
    fn read_varint(&mut self) -> Result<u64, encode::Error> {
        match self.read_u8()? {
            0xFF => {
                let x = self.read_u64()?;
                if x < 0x100000000 {
                    Err(encode::Error::NonMinimalVarInt)
                } else {
                    Ok(x)
                }
            }
            0xFE => {
                let x = self.read_u32()?;
                if x < 0x10000 {
                    Err(encode::Error::NonMinimalVarInt)
                } else {
                    Ok(x as u64)
                }
            }
            0xFD => {
                let x = self.read_u16()?;
                if x < 0xFD {
                    Err(encode::Error::NonMinimalVarInt)
                } else {
                    Ok(x as u64)
                }
            }
            n => Ok(n as u64),
        }
    }
}
