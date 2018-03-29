//! AES random-number generator implementation using AES-NI instruction set.
//!
//! This is port of https://github.com/jedisct1/aes-stream.
//!
//! This crate does not implement any software fallback and does not
//! automatically check CPUID, so if you are using this crate make sure to run
//! software on an appropriate hardware or to use software fallback with runtime
//! detection of AES-NI availability (e.g. by using the
//! [`cupid`](https://crates.io/crates/cupid) crate).
//!
//! When using this crate do not forget to enable `aes` target feature,
//! otherwise you will get an empty crate. You can do it either by using
//! `RUSTFLAGS="-C target-feature=+aes"` or by editing your `.cargo/config`.
//!
//! This crate currently requires nigthly Rust compiler due to the
//! usage of unstable `cfg_target_feature` and `stdsimd` features.
#![feature(cfg_target_feature)]
#![feature(target_feature)]
#![feature(stdsimd)]
#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#![cfg(target_feature = "aes")]

extern crate rand_core;

use std::fmt;

use rand_core::{BlockRngCore, CryptoRng, RngCore, SeedableRng, Error};
use rand_core::impls::BlockRng;

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Trait for casting types to byte slices.
pub trait AsByteSliceMut {
    /// Return a mutable reference to self as a byte slice
    fn as_byte_slice_mut<'a>(&'a mut self) -> &'a mut [u8];

    /// Call `to_le` on each element (i.e. byte-swap on Big Endian platforms).
    fn to_le(&mut self);
}

impl AsByteSliceMut for [u8] {
    fn as_byte_slice_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self
    }

    fn to_le(&mut self) {}
}

macro_rules! impl_as_byte_slice {
    ($t:ty) => {
        impl AsByteSliceMut for [$t] {
            fn as_byte_slice_mut<'a>(&'a mut self) -> &'a mut [u8] {
                unsafe {
                    ::std::slice::from_raw_parts_mut(&mut self[0]
                        as *mut $t
                        as *mut u8,
                        self.len() * ::std::mem::size_of::<$t>()
                    )
                }
            }

            fn to_le(&mut self) {
                for x in self {
                    *x = x.to_le();
                }
            }
        }
    }
}

impl_as_byte_slice!(u32);

const AESRNG_BUFSIZE: usize = 32;

impl<T> AsByteSliceMut for [T; AESRNG_BUFSIZE] where [T]: AsByteSliceMut {
    fn as_byte_slice_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self[..].as_byte_slice_mut()
    }

    fn to_le(&mut self) {
        self[..].to_le()
    }
}

// This is for AES128. AES256 is not implemented for now.
const ROUNDS: usize = 10;
const SEEDBYTES: usize = 32;

type RoundKeys = [__m128i; ROUNDS + 1];

macro_rules! drc {
    ($round:expr, $rc:expr, $s:ident, $t:ident, $round_keys:expr) => (
        $s = _mm_aeskeygenassist_si128($t, $rc);
        $round_keys[$round] = $t;
        $t = _mm_xor_si128($t, _mm_slli_si128($t, 4));
        $t = _mm_xor_si128($t, _mm_slli_si128($t, 8));
        $t = _mm_xor_si128($t, _mm_shuffle_epi32($s, 0xff));
    );
}

fn aes_key_expand_128(round_keys: &mut RoundKeys, mut t: __m128i) {
    let mut s: __m128i;
    unsafe {
        drc!(0, 1, s, t, round_keys);
        drc!(1, 2, s, t, round_keys);
        drc!(2, 4, s, t, round_keys);
        drc!(3, 8, s, t, round_keys);
        drc!(4, 16, s, t, round_keys);
        drc!(5, 32, s, t, round_keys);
        drc!(6, 64, s, t, round_keys);
        drc!(7, 128, s, t, round_keys);
        drc!(8, 27, s, t, round_keys);
        drc!(9, 54, s, t, round_keys);
    }
    round_keys[10] = t;
}

/// A fast-key-erasure random-number generator using AES-NI.
///
/// This is designed to fill large buffers quickly with random data.
#[repr(align(16))]
#[derive(Clone)]
pub struct AesCore {
    round_keys: RoundKeys,
    counter: __m128i,
}

macro_rules! compute_rounds {
    ($n:expr, $c:ident, $r:ident, $s:ident, $round_keys:expr) => (
        unsafe {
            $r[$n] = _mm_aesenc_si128(_mm_xor_si128($c[$n], $round_keys[0]), $round_keys[1]);
            $r[$n] = _mm_aesenc_si128(_mm_aesenc_si128($r[$n], $round_keys[2]), $round_keys[3]);
            $r[$n] = _mm_aesenc_si128(_mm_aesenc_si128($r[$n], $round_keys[4]), $round_keys[5]);
            $s[$n] = $r[$n];
            $r[$n] = _mm_aesenc_si128(_mm_aesenc_si128($r[$n], $round_keys[6]), $round_keys[7]);
            $r[$n] = _mm_aesenc_si128(_mm_aesenc_si128($r[$n], $round_keys[8]), $round_keys[9]);
            $r[$n] = _mm_xor_si128($s[$n], _mm_aesenclast_si128($r[$n], $round_keys[10]));
        }
    );
}

impl AesCore {
    /// Fill the given buffer with random data.
    ///
    /// Erases the key after filling the buffer.
    pub fn fill(&mut self, buffer: &mut [u8]) {
        let zero = unsafe { _mm_set_epi64x(0, 0) };
        let one = unsafe { _mm_set_epi64x(0, 1) };
        let two = unsafe { _mm_set_epi64x(0, 2) };
        let mut c = [zero; 8];
        let mut r = [zero; 8];
        let mut s = [zero; 8];

        c[0] = self.counter;
        let mut remaining = buffer.len();
        let mut buffer = buffer.as_mut_ptr();
        while remaining > 128 {
            unsafe {
                c[1] = _mm_add_epi64(c[0], one);
                c[2] = _mm_add_epi64(c[0], two);
                c[3] = _mm_add_epi64(c[2], one);
                c[4] = _mm_add_epi64(c[2], two);
                c[5] = _mm_add_epi64(c[4], one);
                c[6] = _mm_add_epi64(c[4], two);
                c[7] = _mm_add_epi64(c[6], one);
            }
            compute_rounds!(0, c, r, s, self.round_keys);
            compute_rounds!(1, c, r, s, self.round_keys);
            compute_rounds!(2, c, r, s, self.round_keys);
            compute_rounds!(3, c, r, s, self.round_keys);
            compute_rounds!(4, c, r, s, self.round_keys);
            compute_rounds!(5, c, r, s, self.round_keys);
            compute_rounds!(6, c, r, s, self.round_keys);
            compute_rounds!(7, c, r, s, self.round_keys);
            unsafe {
                c[0] = _mm_add_epi64(c[7], one);
                _mm_storeu_si128(buffer.offset(0) as *mut __m128i, r[0]);
                _mm_storeu_si128(buffer.offset(16) as *mut __m128i, r[1]);
                _mm_storeu_si128(buffer.offset(32) as *mut __m128i, r[2]);
                _mm_storeu_si128(buffer.offset(48) as *mut __m128i, r[3]);
                _mm_storeu_si128(buffer.offset(64) as *mut __m128i, r[4]);
                _mm_storeu_si128(buffer.offset(80) as *mut __m128i, r[5]);
                _mm_storeu_si128(buffer.offset(96) as *mut __m128i, r[6]);
                _mm_storeu_si128(buffer.offset(112) as *mut __m128i, r[7]);
                buffer = buffer.offset(128);
            }
            remaining -= 128;
        }
        while remaining > 32 {
            c[1] = unsafe { _mm_add_epi64(c[0], one) };
            compute_rounds!(0, c, r, s, self.round_keys);
            compute_rounds!(1, c, r, s, self.round_keys);
            unsafe {
                c[0] = _mm_add_epi64(c[1], one);
                _mm_storeu_si128(buffer.offset(0) as *mut __m128i, r[0]);
                _mm_storeu_si128(buffer.offset(16) as *mut __m128i, r[1]);
                buffer = buffer.offset(32);
            }
            remaining -= 32;
        }
        while remaining > 16 {
            compute_rounds!(0, c, r, s, self.round_keys);
            unsafe {
                c[0] = _mm_add_epi64(c[0], one);
                _mm_storeu_si128(buffer as *mut __m128i, r[0]);
                buffer = buffer.offset(16);
            }
            remaining -= 16;
        }
        if remaining > 0 {
            compute_rounds!(0, c, r, s, self.round_keys);
            unsafe {
                #[repr(align(16))]
                let mut t: [u8; 16] = std::mem::uninitialized();
                let t = t.as_mut_ptr();
                c[0] = _mm_add_epi64(c[0], one);
                _mm_storeu_si128(t as *mut __m128i, r[0]);
                for i in 0..remaining {
                    buffer.add(i).write(t.add(i).read());
                }
            }
        }
        self.counter = c[0];

        c[0] = unsafe { _mm_xor_si128(c[0], _mm_set_epi64x(1 << 63, 0)) };
        compute_rounds!(0, c, r, s, self.round_keys);
        aes_key_expand_128(&mut self.round_keys, r[0]);
    }
}

impl SeedableRng for AesCore {
    type Seed = [u8; SEEDBYTES];

    /// Create a new `AesCore` using the given seed.
    fn from_seed(seed: [u8; SEEDBYTES]) -> AesCore {
        let zero = unsafe { _mm_set_epi64x(0, 0) };
        let mut round_keys: RoundKeys = [zero; ROUNDS + 1];
        let key = seed.as_ptr() as *const __m128i;
        let counter = unsafe { seed.as_ptr().offset(16) } as *const __m128i;

        aes_key_expand_128(&mut round_keys, unsafe { _mm_loadu_si128(key) });

        AesCore {
            round_keys,
            counter: unsafe { _mm_loadu_si128(counter) },
        }
    }
}

// Custom Debug implementation that does not expose the internal state
impl fmt::Debug for AesCore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AesCore {{}}")
    }
}

impl BlockRngCore for AesCore {
    type Item = u32;
    type Results = [u32; AESRNG_BUFSIZE];

    fn generate(&mut self, results: &mut Self::Results) {
        self.fill(results.as_byte_slice_mut())
    }
}


/// A fast-key-erasure random-number generator using AES-NI.
///
/// Internally, it uses a 128 byte buffer for generating integers. When the
/// buffer is consumed, the key of the RNG is erased.
///
/// Using `fill`, `fill_bytes` or `try_fill_bytes` always erases the key after
/// filling the buffer. This implies that `next_u32` and `next_u64` will not
/// generate the same results.
#[derive(Clone, Debug)]
pub struct AesRng(BlockRng<AesCore>);

impl RngCore for AesRng {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.core.fill(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.0.core.fill(dest))
    }
}

impl SeedableRng for AesRng {
    type Seed = <AesCore as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng::<AesCore>::from_seed(seed))
    }

    fn from_rng<R: RngCore>(rng: R) -> Result<Self, Error> {
        BlockRng::<AesCore>::from_rng(rng).map(|rng| AesRng(rng))
    }
}

impl CryptoRng for AesRng {}

#[cfg(test)]
mod tests {
    use std::simd::u8x16;
    extern crate itertools;

    use self::itertools::Itertools;

    use super::*;

    #[test]
    fn size() {
        assert_eq!(std::mem::size_of::<AesCore>(), (ROUNDS + 1) * 16 + 16);
    }

    #[test]
    fn from_seed() {
        let rng = AesCore::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ]);
        {
            let mut hex = String::new();
            for key in rng.round_keys.iter() {
                let v = unsafe { std::mem::transmute::<__m128i, u8x16>(*key) };
                for i in 0..16 {
                    hex.push_str(&format!("{:02x}", v.extract(i)));
                }
            }
            let expected = "000102030405060708090a0b0c0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5";
            assert_eq!(hex, expected);
        }
        {
            let mut hex = String::new();
            let v = unsafe { std::mem::transmute::<__m128i, u8x16>(rng.counter) };
            for i in 0..16 {
                hex.push_str(&format!("{:02x}", v.extract(i)));
            }
            let expected = "000102030405060708090a0b0c0d0e0f";
            assert_eq!(hex, expected);
        }
    }

    #[test]
    fn fill() {
        let mut rng = AesCore::from_seed([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ]);

        let mut buf = vec![0; 200];
        rng.fill(&mut buf);
        let hex = format!("{:02x}", buf.iter().format(""));
        let expected = "ddc1766018f72b77a8218c6593de2788f2d1e380d80f0c4d0fc2c294167b8f54a891572bf85fa4c4577a0af946d8a7c0c0b7c4efc6c580ded5616d6c99e2012f37f3c0ccc8815a805fc312cc59ecf9bb77723f91877423bed3f5c2204b17f0cd440543c647c4d1c55b7a5700041484ed3680785e09f51a77845578d51c7276cc19de1941f33ad0112665e9771aba4e07a204537666a96d6f9089497ca50810f5007940a574ef767e6aa7dc1b657bea655e6969c424c173fa346fb6f88412db459c6c0f6fc4c8de91";
        assert_eq!(hex, expected);
    }
}
