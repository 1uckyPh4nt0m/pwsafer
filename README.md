pwsafe
======

A Rust library for reading and writing [Password Safe](https://www.pwsafe.org/) databases.

Updated version of [pwsafe](https://crates.io/crates/pwsafe). Fixed dependancy issues due to yanked crate [block-cipher-trait](https://crates.io/crates/block-cipher-trait/0.5.3). PwsafeReader decrypts the whole psafe3 file in the [new](https://github.com/1uckyPh4nt0m/pwsafe-0.1.3/blob/c14c449948c73fda1955d0b5f6f00aba87470303/src/reader.rs#L136-L141) method and PwsafeWriter encrypts and writes fields on call to [finish](https://github.com/1uckyPh4nt0m/pwsafe-0.1.3/blob/c14c449948c73fda1955d0b5f6f00aba87470303/src/writer.rs#L151-L155). This was done because [block-modes](https://crates.io/crates/block-modes/0.8.1) consumes the BlockMode instance when calling [encrypt](https://docs.rs/block-modes/0.8.1/src/block_modes/traits.rs.html#57-62) and [decrypt](https://docs.rs/block-modes/0.8.1/src/block_modes/traits.rs.html#68-75).