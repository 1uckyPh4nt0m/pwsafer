use block_modes::block_padding::{ZeroPadding};
use block_modes::{BlockMode, Cbc, Ecb};
use block_modes::cipher::NewBlockCipher;
use byteorder::{LittleEndian, ReadBytesExt};
use field::PwsafeHeaderField;
use hmac::{crypto_mac, Hmac, Mac, NewMac};
use key::hash_password;
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::fmt;
use std::io::{self, Cursor, Read};
use twofish::{Twofish, cipher::generic_array::GenericArray};

/// A specialized `Result` type for Password Safe database reader.
pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
/// Password Safe database reader error.
pub enum Error {
    /// Incorrect file signature, file is not a password safe database.
    InvalidTag,
    /// Invalid password.
    InvalidPassword,
    /// Invalid header (mandatory version field is missing or has wrong length).
    InvalidHeader,
    /// Invalid key for block cipher
    InvalidCipherKey,
    /// An I/O error.
    IoError(io::Error),
    /// HMAC error.
    MacError(crypto_mac::MacError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "Not a Password Safe database file"),
            Error::InvalidPassword => write!(f, "Invalid password"),
            Error::InvalidHeader => write!(f, "Invalid header"),
            Error::InvalidCipherKey => write!(f, "Invalid block cipher key"),
            Error::IoError(ref e) => e.fmt(f),
            Error::MacError(ref e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<crypto_mac::MacError> for Error {
    fn from(err: crypto_mac::MacError) -> Error {
        Error::MacError(err)
    }
}

type TwofishCbc = Cbc<Twofish, ZeroPadding>;
type HmacSha256 = Hmac<Sha256>;

/// Password safe reader.
///
/// ```rust
/// use pwsafe::PwsafeReader;
/// use std::fs::File;
/// use std::io::BufReader;
///
/// let filename = "tests/pwsafe.psafe3";
/// let file = BufReader::new(File::open(filename).unwrap());
/// let mut db = PwsafeReader::new(file, b"password").unwrap();
/// let version = db.read_version().unwrap();
/// println!("Version is {:x}", version);
/// while let Some((field_type, field_data)) = db.read_field().unwrap() {
///     println!("Read field of type {} and length {}", field_type, field_data.len());
/// }
/// db.verify().unwrap();
/// ```
pub struct PwsafeReader<R> {
    _inner: R,
    buffer: Cursor<Vec<u8>>,
    hmac: HmacSha256,
    /// Number of iterations
    iter: u32,
}

impl<R: Read> PwsafeReader<R> {
    /// Creates a new `PwsafeReader` with the given password and reads ps3db data into buffer.
    pub fn new(mut inner: R, password: &[u8]) -> Result<Self> {
        let mut tag = [0; 4];
        if inner.read_exact(&mut tag).is_err() {
            return Err(Error::InvalidTag);
        };

        if &tag != b"PWS3" {
            return Err(Error::InvalidTag);
        }

        let mut salt = [0; 32];
        inner.read_exact(&mut salt)?;
        let iter = inner.read_u32::<LittleEndian>()?;
        let mut truehash = [0; 32];
        inner.read_exact(&mut truehash)?;

        let mut k = [0u8; 32];
        let mut l = [0u8; 32];
        let mut iv = [0u8; 16];
        inner.read_exact(&mut k)?;
        inner.read_exact(&mut l)?;
        inner.read_exact(&mut iv)?;

        let key = hash_password(&salt, iter, password);

        let mut hasher = Sha256::default();
        hasher.update(&key);
        if hasher.finalize().as_slice() != truehash {
            return Err(Error::InvalidPassword);
        }
        
        let twofish_cipher = Twofish::new_from_slice(&key).unwrap();
        let mut ecb_cipher = Ecb::<&Twofish, ZeroPadding>::new(&twofish_cipher, &GenericArray::default());
        ecb_cipher.decrypt(&mut k).unwrap();
        ecb_cipher = Ecb::<&Twofish, ZeroPadding>::new(&twofish_cipher, &GenericArray::default());
        ecb_cipher.decrypt(&mut l).unwrap();

        let cbc_cipher = TwofishCbc::new_from_slices(&k, &iv).unwrap();

        let hmac = HmacSha256::new_from_slice(&l).unwrap();

        let mut buffer = Vec::new();
        inner.read_to_end(&mut buffer).unwrap();
        let mut eof_hmac = buffer[buffer.len()-48..buffer.len()].to_vec();   //48 because of pws3eof and hmac
        buffer = buffer[0..buffer.len()-48].to_vec();
        cbc_cipher.decrypt(&mut buffer).unwrap();
        buffer.append(&mut eof_hmac);

        Ok(PwsafeReader {
            _inner: inner,
            buffer: Cursor::new(buffer),
            hmac,
            iter,
        })
    }

    /// Reads the database version field.
    pub fn read_version(&mut self) -> Result<u16> {
        let (field_type, data) = self.read_field()?.unwrap();
        let field = PwsafeHeaderField::new(field_type, data);
        if let Ok(PwsafeHeaderField::Version(version)) = field {
            return Ok(version);
        }
        Err(Error::InvalidHeader)
    }

    /// Reads a field.
    ///
    /// Returns field type and contents or `None` if EOF block is encountered.
    pub fn read_field(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        let mut block = [0u8; 16];
        self.buffer.read_exact(&mut block)?;

        let eof = b"PWS3-EOFPWS3-EOF";
        if &block == eof {
            return Ok(None);
        }

        let mut cursor = Cursor::new(&block);
        let field_length = cursor.read_u32::<LittleEndian>().unwrap() as usize;
        let field_type = cursor.read_u8().unwrap();

        let mut data = Vec::new();
        data.reserve(field_length);
        data.extend_from_slice(&block[5..5 + min(11, field_length)]);

        // Read the rest of the field
        let mut i = 11;
        while i < field_length {
            self.buffer.read_exact(&mut block)?;
            data.extend_from_slice(&block[0..min(16, field_length - i)]);
            i += 16;
        }
        self.hmac.update(&data);

        assert_eq!(data.len(), field_length);
        Ok(Some((field_type, data)))
    }

    /// Reads HMAC and checks the database integrity.
    ///
    /// This function must be called after reading the last field in the database.
    pub fn verify(&mut self) -> Result<()> {
        let mut mac = [0u8; 32];
        self.buffer.read_exact(&mut mac)?;
        self.hmac.clone().verify(&mac)?;
        Ok(())
    }

    /// Returns the number of iterations used for key stretching.
    pub fn get_iter(&self) -> u32 {
        self.iter
    }
}
