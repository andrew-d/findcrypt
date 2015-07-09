use std::mem::size_of;
use std::marker::PhantomData;

use byteorder::{ByteOrder, BigEndian, LittleEndian};


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

impl AsBytes for u8 {
    fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize {
        buf[0] = *self;
        1
    }
}

as_bytes_impl!(u16, write_u16);
as_bytes_impl!(u32, write_u32);
as_bytes_impl!(u64, write_u64);

impl<'a, T: AsBytes> AsBytes for &'a T {
    fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize {
        (**self).as_bytes::<O>(buf)
    }
}

impl<'a, T: AsBytes> AsBytes for &'a mut T {
    fn as_bytes<O: ByteOrder>(&self, buf: &mut [u8]) -> usize {
        (**self).as_bytes::<O>(buf)
    }
}


#[derive(Debug)]
pub struct EndianWrapper<'a, T: AsBytes + 'a>(pub &'a [T]);


impl<'a, T: AsBytes + 'a> EndianWrapper<'a, T> {
    pub fn iter_bytes<O: ByteOrder>(&self) -> EndianWrapperIter<T, O> {
        EndianWrapperIter {
            underlying: self,
            count: 0,
            buf: [0; 8],
            offset: 0,
            valid: 0,
            phantom: PhantomData,
        }
    }
}


pub struct EndianWrapperIter<'a, T, O>
where T: AsBytes + 'static,
      O: ByteOrder
{
    underlying: &'a EndianWrapper<'a, T>,
    count: usize,

    buf: [u8; 8],
    offset: usize,
    valid: usize,

    phantom: PhantomData<O>,
}


impl<'a, T: AsBytes, O: ByteOrder> Iterator for EndianWrapperIter<'a, T, O> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.offset < self.valid {
            let curr = self.buf[self.offset];
            self.offset += 1;
            return Some(curr);
        }

        let len = {
            let &EndianWrapper(ref underlying) = self.underlying;
            underlying.len()
        };

        if self.count >= len {
            return None;
        }

        let &EndianWrapper(ref underlying) = self.underlying;
        let it = &underlying[self.count];
        self.count += 1;

        {
            self.valid = it.as_bytes::<O>(&mut self.buf);
        }

        self.offset = 1;
        Some(self.buf[0])
    }
}



#[cfg(test)]
static TEST_CONSTANTS: EndianWrapper<'static, u32> = EndianWrapper(&[
    0x12345678,
    0x00000001,
    0xFFFFFFFF,
]);


#[test]
fn test_as_bytes_be() {
    let bytes = TEST_CONSTANTS.iter_bytes::<BigEndian>().collect::<Vec<u8>>();

    assert_eq!(bytes, &[
        0x12, 0x34, 0x56, 0x78,
        0x00, 0x00, 0x00, 0x01,
        0xFF, 0xFF, 0xFF, 0xFF,
    ]);
}

#[test]
fn test_as_bytes_le() {
    let bytes = TEST_CONSTANTS.iter_bytes::<LittleEndian>().collect::<Vec<u8>>();

    assert_eq!(bytes, &[
        0x78, 0x56, 0x34, 0x12,
        0x01, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF,
    ]);
}
