use rand::rngs::OsRng;
use rand::CryptoRng;
use rand::Error;
use rand::RngCore;

pub struct StrandRng;

impl CryptoRng for StrandRng {}

impl RngCore for StrandRng {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest)
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        OsRng.try_fill_bytes(dest)
    }
}
