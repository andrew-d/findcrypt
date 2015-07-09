use std::io::Cursor;
use std::marker::PhantomData;
use std::mem::size_of;

use byteorder::{ByteOrder, WriteBytesExt, BigEndian, LittleEndian};


macro_rules! generate_iterator {
    ($name:ident, $t:ty, $funcname:ident) => {
        struct $name<'a, E> {
            // Underlying array to pull from.
            array: &'a [$t],
            array_offset: usize,

            // Buffer for the encoding of the current underlying
            // element.
            buf: [u8; 8],

            // Number of bytes valid in the current element.
            valid: usize,

            // Offset in the buffer.
            offset: usize,

            // Phantom data for the endianness.
            endian: PhantomData<E>,
        }

        impl<'a, E: ByteOrder> $name<'a, E> {
            pub fn new(arr: &[$t]) -> $name<E> {
                $name {
                    array: arr,
                    array_offset: 0,
                    buf: [0; 8],
                    valid: 0,
                    offset: 0,
                    endian: PhantomData,
                }
            }
        }

        impl<'a, E: ByteOrder> Iterator for $name<'a, E> {
            type Item = u8;

            fn next(&mut self) -> Option<u8> {
                // If we have any more bytes in our buffer, return them.
                if self.offset < self.valid {
                    let ret = Some(self.buf[self.offset]);
                    self.offset += 1;
                    return ret;
                }

                // Otherwise, we need to fill our buffer.  See if we can get a value
                // from the underlying array.
                if self.array_offset >= self.array.len() {
                    return None;
                }

                {
                    let curr = self.array[self.array_offset];
                    self.array_offset += 1;

                    let mut writer = Cursor::new(&mut self.buf[..]);
                    // TODO: endianness
                    writer.$funcname::<E>(curr).unwrap();
                }

                // We have this many bytes.
                self.valid = size_of::<$t>();

                // Offset of once since we return the first value, below.
                self.offset = 1;

                // Return the first item.
                Some(self.buf[0])
            }
        }

    };
}

generate_iterator!(ByteIterator_u16, u16, write_u16);
generate_iterator!(ByteIterator_u32, u32, write_u32);
generate_iterator!(ByteIterator_u64, u64, write_u64);


#[test]
fn test_u32_iter_be() {
    static TEST_ARR: &'static [u32] = &[
        0x12345678,
        0x98765432,
    ];

    let mut arr = ByteIterator_u32::<BigEndian>::new(TEST_ARR);

    assert_eq!(arr.next(), Some(0x12));
    assert_eq!(arr.next(), Some(0x34));
    assert_eq!(arr.next(), Some(0x56));
    assert_eq!(arr.next(), Some(0x78));

    assert_eq!(arr.next(), Some(0x98));
    assert_eq!(arr.next(), Some(0x76));
    assert_eq!(arr.next(), Some(0x54));
    assert_eq!(arr.next(), Some(0x32));

    assert_eq!(arr.next(), None);
}

#[test]
fn test_u32_iter_le() {
    static TEST_ARR: &'static [u32] = &[
        0x12345678,
        0x98765432,
    ];

    let mut arr = ByteIterator_u32::<LittleEndian>::new(TEST_ARR);

    assert_eq!(arr.next(), Some(0x78));
    assert_eq!(arr.next(), Some(0x56));
    assert_eq!(arr.next(), Some(0x34));
    assert_eq!(arr.next(), Some(0x12));

    assert_eq!(arr.next(), Some(0x32));
    assert_eq!(arr.next(), Some(0x54));
    assert_eq!(arr.next(), Some(0x76));
    assert_eq!(arr.next(), Some(0x98));

    assert_eq!(arr.next(), None);
}



pub trait BytesIterator {
    fn get_bytes<E: ByteOrder + 'static>() -> Box<Iterator<Item=u8>>;
}



macro_rules! make_constants {
    ($name:ident, $it:ident, $t:ty, $vals:expr) => {
        pub struct $name;

        impl BytesIterator for $name {
            fn get_bytes<E: ByteOrder + 'static>() -> Box<Iterator<Item=u8>> {
                static arr: &'static [$t] = & $vals;

                let it = $it::<E>::new(arr);

                Box::new(it) as Box<Iterator<Item=u8>>
            }
        }
    };
}


#[cfg(test)]
make_constants!(ConstantsForTesting, ByteIterator_u32, u32, [
    0x12345678,
]);

#[test]
fn test_constants() {
    let mut it = ConstantsForTesting::get_bytes::<BigEndian>();
    let bytes = it.collect::<Vec<u8>>();

    assert_eq!(bytes, &[0x12, 0x34, 0x56, 0x78]);
}


make_constants!(SHA256_constants, ByteIterator_u32, u32, [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
