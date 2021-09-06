use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, Cbc, Ecb};
use byteorder::{LittleEndian, WriteBytesExt};
use hmac::{Hmac, Mac, NewMac};
use key::hash_password;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::io;
use std::io::{Cursor, Write};
use std::result::Result;
use twofish::cipher::generic_array::{GenericArray};
use twofish::Twofish;

type TwofishEcb = Ecb<Twofish, ZeroPadding>;
type TwofishCbc = Cbc<Twofish, ZeroPadding>;
type HmacSha256 = Hmac<Sha256>;

/// Password safe writer.
///
/// # Examples
///
/// An example shows how to create an empty database.
/// ```no_run
/// use pwsafe::PwsafeWriter;
/// use std::fs::File;
/// use std::io::BufWriter;
///
/// let filename = "pwsafe.psafe3";
/// let file = BufWriter::new(File::create(filename).unwrap());
/// let mut db = PwsafeWriter::new(file, 2048, b"password").unwrap();
/// let version = [0x0eu8, 0x03u8];
/// let empty = [0u8, 0];
/// db.write_field(0x00, &version).unwrap(); // Version field
/// db.write_field(0xff, &empty).unwrap(); // End of header
/// db.finish().unwrap(); // EOF and HMAC
/// ```
pub struct PwsafeWriter<W> {
    inner: W,
    cipher: TwofishCbc,
    hmac: HmacSha256,
}

impl<W: Write> PwsafeWriter<W> {
    /// Creates a new `PwsafeWriter` with the given password.
    pub fn new(mut inner: W, iter: u32, password: &[u8]) -> Result<Self, io::Error> {
        inner.write_all(b"PWS3")?;

        let mut salt = [0u8; 32];
        //let mut r = OsRng::new().unwrap();
        
        OsRng.fill_bytes(&mut salt);
        inner.write_all(&salt)?;
        inner.write_u32::<LittleEndian>(iter)?;

        let key = hash_password(&salt, iter, password);

        let mut hasher = Sha256::default();
        hasher.update(&key);
        let hash = hasher.finalize();
        inner.write_all(&hash)?;

        let mut k = [0u8; 32];
        let mut l = [0u8; 32];
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut k);
        OsRng.fill_bytes(&mut l);
        OsRng.fill_bytes(&mut iv);
        //let iv = GenericArray::from_slice(&iv);

        //let cbc_cipher = TwofishCbc::new_varkey(&k, &iv).unwrap();
        let cbc_cipher = TwofishCbc::new_from_slices(&k, &iv).unwrap();
        //let sha256_hmac = HmacSha256::new_varkey(&l).unwrap();
        let sha256_hmac = HmacSha256::new_from_slice(&l).unwrap();

        //let mut ecb_cipher = TwofishEcb::new_varkey(&key).unwrap();
        let mut ecb_cipher = TwofishEcb::new_fix(&key, &GenericArray::default());
        ecb_cipher.encrypt(&mut k, 0).unwrap();
        ecb_cipher = TwofishEcb::new_fix(&key, &GenericArray::default());
        ecb_cipher.encrypt(&mut l, 0).unwrap();

        inner.write_all(&k)?;
        inner.write_all(&l)?;
        inner.write_all(&iv)?;

        let w = PwsafeWriter {
            inner,
            cipher: cbc_cipher,
            hmac: sha256_hmac,
        };
        Ok(w)
    }

    /// Encrypts and writes one field.
    pub fn write_field(&mut self, field_type: u8, data: &[u8]) -> Result<(), io::Error> {
        let mut i: usize = 0;
        let mut block = [0u8; 16];
        let mut cur = Cursor::new(Vec::new());
        cur.write_u32::<LittleEndian>(data.len() as u32)?;
        cur.write_u8(field_type)?;
        //let mut r = OsRng::new().unwrap();

        self.hmac.update(&data);
        loop {
            let l = min(16 - cur.get_ref().len(), data.len() - i);
            cur.write_all(&data[i..i + l])?;

            if l == 0 {
                i += 16
            } else {
                i += l;
            }

            let v = cur.into_inner();
            let vlen = v.len();
            block[0..vlen].copy_from_slice(&v);
            OsRng.fill_bytes(&mut block[vlen..16]); // Pad with random bytes
            self.cipher.encrypt(&mut block, 0).unwrap();
            self.inner.write_all(&block)?;

            cur = Cursor::new(Vec::new());
            if i >= data.len() {
                break;
            }
        }
        Ok(())
    }

    /// Writes EOF block and HMAC.
    pub fn finish(&mut self) -> Result<(), io::Error> {
        self.inner.write_all(b"PWS3-EOFPWS3-EOF")?;
        self.inner.write_all(&self.hmac.clone().finalize().into_bytes())?;
        Ok(())
    }
}
