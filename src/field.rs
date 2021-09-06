use byteorder::{LittleEndian, ReadBytesExt};
use std::fmt;
use std::io;
use std::io::Cursor;
use std::string;

/// A specialized `Result` type for Password Safe field parsers.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Password Safe field parsing error.
#[derive(Debug)]
pub enum Error {
    /// Incorrect field length.
    InvalidLength,
    /// An I/O error.
    IoError(io::Error),
    /// Error converting bytes to UTF-8 string.
    FromUtf8Error(string::FromUtf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidLength => write!(f, "Invalid field length"),
            Error::IoError(ref e) => e.fmt(f),
            Error::FromUtf8Error(ref e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Error {
        Error::FromUtf8Error(err)
    }
}

fn parse_u16(data: Vec<u8>) -> Result<u16> {
    if data.len() != 2 {
        return Err(Error::InvalidLength);
    }
    let mut cursor = Cursor::new(data);
    let i = cursor.read_u16::<LittleEndian>()?;
    Ok(i)
}

fn parse_u32(data: Vec<u8>) -> Result<u32> {
    if data.len() != 4 {
        return Err(Error::InvalidLength);
    }
    let mut cursor = Cursor::new(data);
    let i = cursor.read_u32::<LittleEndian>()?;
    Ok(i)
}

/// Password Safe header field.
#[derive(Debug)]
pub enum PwsafeHeaderField {
    /// Version
    Version(u16),
    /// UUID
    Uuid([u8; 16]),
    /// Non-default preferences
    Preferences(String),
    /// Tree Display Status
    TreeDisplayStatus(String),
    /// Timestamp of last save
    LastSaveTimestamp(u32),
    /// Who performed last save
    LastSaveWho(String),
    /// What performed last save
    LastSaveWhat(String),
    /// Last saved by user
    LastSaveUser(String),
    /// Last saved on host
    LastSaveHost(String),
    /// Database Name
    DatabaseName(String),
    /// Database Description
    DatabaseDescription(String),
    /// Database Filters
    DatabaseFilters(String),
    /// Recently Used Entries
    RecentlyUsedEntries(String),
    /// Named Password Policies
    NamedPasswordPolicies(String),
    /// EmptyGroups
    EmptyGroups(String),
    /// Yubico
    Yubico(String),
    /// Timestamp of last master password change
    LastMasterPasswordChange(u32),
    /// Unknown field type stored as-is
    Blob(Vec<u8>),
    /// End of header
    EndOfHeader,
}

impl PwsafeHeaderField {
    pub fn new(field_type: u8, data: Vec<u8>) -> Result<Self> {
        let res = match field_type {
            0x00 => {
                let version = parse_u16(data)?;
                PwsafeHeaderField::Version(version)
            }
            0x01 => {
                if data.len() != 16 {
                    return Err(Error::InvalidLength);
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&data.as_slice());
                PwsafeHeaderField::Uuid(uuid)
            }
            0x02 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::Preferences(s)
            }
            0x03 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::TreeDisplayStatus(s)
            }
            0x04 => {
                let timestamp = parse_u32(data)?;
                PwsafeHeaderField::LastSaveTimestamp(timestamp)
            }
            0x05 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::LastSaveWho(s)
            }
            0x06 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::LastSaveWhat(s)
            }
            0x07 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::LastSaveUser(s)
            }
            0x08 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::LastSaveHost(s)
            }
            0x09 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::DatabaseName(s)
            }
            0x0a => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::DatabaseDescription(s)
            }
            0x0b => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::DatabaseFilters(s)
            }
            // 0x0c, 0x0d, 0x0e are reserved
            0x0f => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::RecentlyUsedEntries(s)
            }
            0x10 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::NamedPasswordPolicies(s)
            }
            0x11 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::EmptyGroups(s)
            }
            0x12 => {
                let s = String::from_utf8(data)?;
                PwsafeHeaderField::Yubico(s)
            }
            0x13 => {
                let timestamp = parse_u32(data)?;
                PwsafeHeaderField::LastMasterPasswordChange(timestamp)
            }
            0xff => PwsafeHeaderField::EndOfHeader,
            _ => PwsafeHeaderField::Blob(data),
        };
        Ok(res)
    }
}

/// Password Safe record field.
#[derive(Debug)]
pub enum PwsafeRecordField {
    /// UUID
    Uuid([u8; 16]),
    /// Group
    Group(String),
    /// Title
    Title(String),
    /// Username
    Username(String),
    /// Notes
    Notes(String),
    /// Password
    Password(String),
    /// Creation time
    CreationTime(u32),
    /// Password modification time
    PasswordModificationTime(u32),
    /// Last access time
    LastAccessTime(u32),
    /// Password expiry time
    PasswordExpiryTime(u32),
    /// Last modification time
    LastModificationTime(u32),
    /// URL
    Url(String),
    /// Autotype
    Autotype(String),
    /// Password history
    PasswordHistory(String),
    /// Password policy
    PasswordPolicy(String),
    /// Password expiry interval
    PasswordExpiryInterval(u32),
    /// Run command
    RunCommand(String),
    /// Double-click action
    DoubleClickAction(u16),
    /// Email address
    EmailAddress(String),
    /// Protected entry
    ProtectedEntry(u8),
    /// Own symbols for password
    OwnSymbolsForPassword(String),
    /// Shift double-click action
    ShiftDoubleClickAction(u16),
    /// Password policy name
    PasswordPolicyName(String),
    /// Entry keyboard shortcut
    EntryKeyboardShortcut(u32),
    /// Two-factor key
    TwoFactorKey(Vec<u8>),
    /// Credit card number
    CreditCardNumber(String),
    /// Credit card expiration
    CreditCardExpiration(String),
    /// Credit card verif. value
    CreditCardVerifValue(String),
    /// Credit card PIN
    CreditCardPin(String),
    /// QR code
    QrCode(String),
    /// Unknown field type stored as-is
    Blob(Vec<u8>),
    /// End of record
    EndOfRecord,
}

impl PwsafeRecordField {
    pub fn new(field_type: u8, data: Vec<u8>) -> Result<Self> {
        let res = match field_type {
            0x01 => {
                if data.len() != 16 {
                    return Err(Error::InvalidLength);
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&data.as_slice());
                PwsafeRecordField::Uuid(uuid)
            }
            0x02 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::Group(s)
            }
            0x03 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::Title(s)
            }
            0x04 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::Username(s)
            }
            0x05 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::Notes(s)
            }
            0x06 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::Password(s)
            }
            0x07 => {
                let timestamp = parse_u32(data)?;
                PwsafeRecordField::CreationTime(timestamp)
            }
            0x08 => {
                let timestamp = parse_u32(data)?;
                PwsafeRecordField::PasswordModificationTime(timestamp)
            }
            0x09 => {
                let timestamp = parse_u32(data)?;
                PwsafeRecordField::LastAccessTime(timestamp)
            }
            0x0a => {
                let timestamp = parse_u32(data)?;
                PwsafeRecordField::PasswordExpiryTime(timestamp)
            }
            // 0x0b is reserved
            0x0c => {
                let timestamp = parse_u32(data)?;
                PwsafeRecordField::LastModificationTime(timestamp)
            }
            0x0d => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::Url(s)
            }
            0x0e => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::Autotype(s)
            }
            0x0f => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::PasswordHistory(s)
            }
            0x10 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::PasswordPolicy(s)
            }
            0x11 => {
                let days = parse_u32(data)?;
                PwsafeRecordField::PasswordExpiryInterval(days)
            }
            0x12 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::RunCommand(s)
            }
            0x13 => {
                let action = parse_u16(data)?;
                PwsafeRecordField::DoubleClickAction(action)
            }
            0x14 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::EmailAddress(s)
            }
            0x15 => {
                if data.len() != 1 {
                    return Err(Error::InvalidLength);
                }
                PwsafeRecordField::ProtectedEntry(data[0])
            }
            0x16 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::OwnSymbolsForPassword(s)
            }
            0x17 => {
                let action = parse_u16(data)?;
                PwsafeRecordField::ShiftDoubleClickAction(action)
            }
            0x18 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::PasswordPolicyName(s)
            }
            0x19 => {
                let shortcut = parse_u32(data)?;
                PwsafeRecordField::EntryKeyboardShortcut(shortcut)
            }
            // 0x1a is reserved
            0x1b => PwsafeRecordField::TwoFactorKey(data),
            0x1c => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::CreditCardNumber(s)
            }
            0x1d => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::CreditCardExpiration(s)
            }
            0x1e => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::CreditCardVerifValue(s)
            }
            0x1f => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::CreditCardPin(s)
            }
            0x20 => {
                let s = String::from_utf8(data)?;
                PwsafeRecordField::QrCode(s)
            }
            0xff => PwsafeRecordField::EndOfRecord,
            _ => PwsafeRecordField::Blob(data),
        };
        Ok(res)
    }
}
