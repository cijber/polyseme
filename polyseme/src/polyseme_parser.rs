use crate::polyseme_builder::{next_ahotp, ContentSet};
use base64::DecodeError;
use ring::digest::{digest, Context, SHA256};
use ring::hmac::{Key, HMAC_SHA256};
use std::collections::HashMap;
use std::convert::TryInto;

pub trait RecordFetcher {
    fn record(&self, name: &str) -> Vec<String>;
}

pub struct PolysemeParser {
    record_fetcher: Box<dyn RecordFetcher>,
    hashed_key: [u8; 32],
    hmac_key: Key,
    counter: u64,
    reached_eof: bool,
    base64_buffer: String,
}

#[derive(Debug)]
pub enum PolysemeParseError {
    Base64DecodingError(DecodeError),
    AlreadyReachedEndOfFile,
    HashVerificationError,
    ExpectedHash,
    EmptyResult,
}

impl From<DecodeError> for PolysemeParseError {
    fn from(err: DecodeError) -> Self {
        PolysemeParseError::Base64DecodingError(err)
    }
}

impl PolysemeParser {
    pub fn new(shared_key: &[u8], record_fetcher: Box<dyn RecordFetcher>) -> PolysemeParser {
        let shared_key = shared_key.to_vec();
        let hmac_key = Key::new(HMAC_SHA256, &shared_key);
        let hashed_key = digest(&SHA256, &shared_key).as_ref().try_into().unwrap();

        PolysemeParser {
            record_fetcher,
            hashed_key,
            hmac_key,
            counter: 0,
            reached_eof: false,
            base64_buffer: "".to_string(),
        }
    }

    pub fn read(&mut self) -> Result<Option<Vec<u8>>, PolysemeParseError> {
        if self.reached_eof {
            return Ok(None);
        }

        let mut buffer = vec![];
        let record_name = next_ahotp(&mut self.counter, &self.hmac_key);
        let mut entries = self.record_fetcher.record(&record_name).into_iter();
        let hash = base64::decode(entries.next().ok_or(PolysemeParseError::EmptyResult)?)?;
        let mut hash_ctx = Context::new(&SHA256);

        while let Some(entry) = entries.next() {
            hash_ctx.update(entry.as_bytes());

            if entry.len() == 44 {
                let data = base64::decode(&entry)?;
                if &data[..] == &self.hashed_key[..] {
                    self.reached_eof = true;

                    buffer.append(&mut base64::decode(&self.base64_buffer)?);
                    break;
                }
            }

            self.base64_buffer += &entry;
            let (to_decode, rest) = self
                .base64_buffer
                .split_at(self.base64_buffer.len() - (self.base64_buffer.len() % 4));
            let mut data = base64::decode(to_decode)?;
            self.base64_buffer = rest.to_string();
            buffer.append(&mut data);
        }

        if hash != hash_ctx.finish().as_ref() {
            return Err(PolysemeParseError::HashVerificationError);
        }

        return Ok(Some(buffer).filter(|x| !x.is_empty()));
    }

    pub fn read_to_end(&mut self) -> Result<Vec<u8>, PolysemeParseError> {
        let mut buffer = vec![];

        while let Some(mut data) = self.read()? {
            buffer.append(&mut data);
        }

        Ok(buffer)
    }
}

impl RecordFetcher for HashMap<String, ContentSet> {
    fn record(&self, name: &str) -> Vec<String> {
        self.get(name)
            .map(|item| item.entries.iter().map(|entry| entry.to_string()).collect())
            .unwrap_or(vec![])
    }
}

pub fn fetch_polyseme<T: 'static + RecordFetcher>(
    shared_key: &[u8],
    record_fetcher: T,
) -> Result<Vec<u8>, PolysemeParseError> {
    PolysemeParser::new(shared_key, Box::new(record_fetcher)).read_to_end()
}
