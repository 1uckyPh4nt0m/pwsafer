// An example showing how to parse Password Safe database content.
//
// Run as: cargo run --example dump ~/.pwsafe/pwsafe.psafe3 password

extern crate pwsafe;

use pwsafe::{PwsafeHeaderField, PwsafeReader, PwsafeRecordField};
use std::env;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let args: Vec<String> = env::args().collect();
    let filename = &args[1];
    let password = &args[2];

    let file = BufReader::new(File::open(filename).unwrap());

    let mut db = PwsafeReader::new(file, password.as_bytes()).unwrap();
    db.read_version().unwrap();

    loop {
        let (field_type, field_data) = db.read_field().unwrap().unwrap();
        let field = PwsafeHeaderField::new(field_type, field_data);
        println!("{:?}", field);
        if field_type == 0xff {
            break;
        }
    }

    while let Some((field_type, field_data)) = db.read_field().unwrap() {
        let field = PwsafeRecordField::new(field_type, field_data);
        println!("{:?}", field);
    }
    db.verify().unwrap();
}
