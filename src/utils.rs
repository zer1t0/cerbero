use crate::core::CredFormat;
use crate::error::Result;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub fn get_ticket_file(
    args_file: Option<String>,
    username: &String,
    cred_format: &CredFormat,
) -> String {
    if let Some(file) = args_file {
        return file;
    }

    if let Some(file) = get_env_ticket_file() {
        return file;
    }

    return format!("{}.{}", username, cred_format);
}

pub fn get_env_ticket_file() -> Option<String> {
    return env::var("KRB5CCNAME").ok();
}

pub fn open_file(filename: &str) -> Result<File> {
    return Ok(File::open(filename).map_err(|error| {
        format!("Unable to open the file '{}': {}", filename, error)
    })?);
}

pub fn new_file_reader(filename: &str) -> Result<BufReader<File>> {
    return Ok(BufReader::new(open_file(filename)?));
}

pub fn new_lines_reader(filename: &str) -> Result<LinesReader> {
    return Ok(LinesReader::new(new_file_reader(filename)?));
}

pub struct LinesReader {
    reader: BufReader<File>,
}

impl LinesReader {
    fn new(reader: BufReader<File>) -> Self {
        return Self { reader };
    }

    pub fn lines(self) -> impl Iterator<Item = String> {
        return self
            .reader
            .lines()
            .filter_map(std::result::Result::ok)
            .filter(|l| !(l.is_empty() || l.starts_with("#")))
            .into_iter();
    }
}

pub fn read_file_lines(filename: &str) -> Result<Vec<String>> {
    let fd = File::open(filename).map_err(|error| {
        format!("Unable to read the file '{}': {}", filename, error)
    })?;
    let file_lines: Vec<String> = BufReader::new(fd)
        .lines()
        .filter_map(std::result::Result::ok)
        .collect();

    return Ok(file_lines);
}
