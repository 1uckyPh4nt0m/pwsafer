//! Password Safe file format reader and writer.
//!
//! This crate provides separate reader and writer for Password Safe database format. It does not
//! impose any internal database representation and can be used to write converters or integrate
//! import/export functionality into existing password managers.
//!
//! Neither reader nor writer require `std::io::Seek` trait implementation from the underlying
//! reader or writer. That is because by design the Password Safe database does not allow random
//! access. Blocks are encrypted in CBC mode and checking the database integrity requires reading
//! the whole file. On the other hand, the database must be rekeyed after each modification, so the
//! whole file must be rewritten from scratch.
//!
//! At this time only version 3 database format is supported.
//!
//! High-level interfaces to parse records are not implemented (yet).

extern crate block_modes;
extern crate byteorder;
extern crate hmac;
extern crate rand;
extern crate sha2;
extern crate twofish;

mod field;
mod key;
mod reader;
mod writer;

pub use self::field::PwsafeHeaderField;
pub use self::field::PwsafeRecordField;
pub use self::reader::PwsafeReader;
pub use self::writer::PwsafeWriter;
