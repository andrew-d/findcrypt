use std::mem::size_of;

use byteorder::{ByteOrder, BigEndian, LittleEndian};

// ----------------------------------------------------------------------

/// This trait is implemented by anything that can write itself as bytes to a
/// user-provided buffer.  The function will panic if the buffer is not large
/// enough to contain the required number of bytes.
pub trait AsBytes {
    fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize;
}

macro_rules! as_bytes_impl {
    ($t:ty, $f:ident) => {
        impl AsBytes for $t {
            fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize {
                O::$f(buf, *self);
                size_of::<$t>()
            }
        }
    };
}

// Manually implemented - byteorder has no `write_u8` function.
impl AsBytes for u8 {
    fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize {
        buf[0] = *self;
        1
    }
}

as_bytes_impl!(u16, write_u16);
as_bytes_impl!(u32, write_u32);
as_bytes_impl!(u64, write_u64);

// Useful implementations for things behind references.
impl<'a, T: AsBytes> AsBytes for &'a T {
    fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize {
        (**self).as_bytes::<O>(buf)
    }
}

// Useful implementations for things behind mutable references.
impl<'a, T: AsBytes> AsBytes for &'a mut T {
    fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize {
        (**self).as_bytes::<O>(buf)
    }
}

// ----------------------------------------------------------------------

/// EndianWrapper is a wrapper that allows converting an entire slice of things
/// that implement `AsBytes` into a single byte vector.
#[derive(Debug)]
pub struct EndianWrapper<'a, T: AsBytes + 'a>(pub &'a [T]);

// ----------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Endianness {
    LittleEndian,
    BigEndian,
}

/// AsByteVec is a trait for things that can convert themselves to vectors of
/// bytes with a given endianness.
pub trait AsByteVec {
    /// This function converts this item into a vector of bytes, using the
    /// given endianness.
    fn as_byte_vec(&self, e: Endianness) -> Vec<u8>;
}

impl<'a, T: AsBytes + 'a> AsByteVec for EndianWrapper<'a, T> {
    fn as_byte_vec(&self, e: Endianness) -> Vec<u8> {
        let &EndianWrapper(ref underlying) = self;

        let mut v = Vec::with_capacity(underlying.len() * size_of::<T>());
        let mut buf = [0; 8];

        if e == Endianness::BigEndian {
            for elem in *underlying {
                let len = elem.as_bytes::<BigEndian>(&mut buf);
                v.extend(&buf[0..len]);
            }
        } else {
            for elem in *underlying {
                let len = elem.as_bytes::<LittleEndian>(&mut buf);
                v.extend(&buf[0..len]);
            }
        }

        v
    }
}

// Useful implementations for things behind references.
impl<'a, T: AsByteVec> AsByteVec for &'a T {
    fn as_byte_vec(&self, e: Endianness) -> Vec<u8> {
        (**self).as_byte_vec(e)
    }
}

// Useful implementations for things behind mutable references.
impl<'a, T: AsByteVec> AsByteVec for &'a mut T {
    fn as_byte_vec(&self, e: Endianness) -> Vec<u8> {
        (**self).as_byte_vec(e)
    }
}

// ----------------------------------------------------------------------

#[cfg(test)]
static TEST_CONSTANTS: EndianWrapper<'static, u32> = EndianWrapper(&[
    0x12345678,
    0x00000001,
    0xFFFFFFFF,
]);


#[test]
fn test_as_bytes_be() {
    let bytes = TEST_CONSTANTS.as_byte_vec(Endianness::BigEndian);

    assert_eq!(bytes, &[
        0x12, 0x34, 0x56, 0x78,
        0x00, 0x00, 0x00, 0x01,
        0xFF, 0xFF, 0xFF, 0xFF,
    ]);
}

#[test]
fn test_as_bytes_le() {
    let bytes = TEST_CONSTANTS.as_byte_vec(Endianness::LittleEndian);

    assert_eq!(bytes, &[
        0x78, 0x56, 0x34, 0x12,
        0x01, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF,
    ]);
}
