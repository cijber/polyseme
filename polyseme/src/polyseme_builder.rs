use ring::digest::{digest, Context, SHA256};
use ring::hmac::{sign, Key, HMAC_SHA256};
use std::convert::TryInto;
use std::fmt::{Debug, Formatter};
use std::{fmt, mem};

#[derive(Clone)]
pub struct ContentSet {
    pub name: String,
    pub size: usize,
    pub entries: Vec<ContentEntry>,
    pub hash_context: Option<Context>,
}

impl PartialEq for ContentSet {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name) && self.entries.eq(&other.entries)
    }
}

impl Debug for ContentSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentSet")
            .field("name", &self.name)
            .field("size", &self.size)
            .field("entries", &self.entries)
            .finish()
    }
}

impl ContentSet {
    pub fn new(name: String) -> ContentSet {
        ContentSet {
            name,
            // Start with integrity hash size
            size: 44,
            hash_context: Some(Context::new(&SHA256)),
            entries: vec![ContentEntry::Hash([0; 32])],
        }
    }

    pub fn calculate_hash(&mut self) {
        if let ContentEntry::Hash(hash) = &mut self.entries[0] {
            let old = mem::replace(&mut self.hash_context, None);
            if let Some(ctx) = old {
                hash.copy_from_slice(&ctx.finish().as_ref());
            }
        } else {
            panic!("First entry of ContentSet should be a hash")
        }
    }

    pub fn add_entry(&mut self, entry: ContentEntry) -> Result<(), ContentEntry> {
        if self.size + entry.dns_size() > u16::MAX as usize {
            return Err(entry);
        }

        self.size += entry.dns_size();
        if let Some(ctx) = &mut self.hash_context {
            ctx.update(entry.to_string().as_bytes());
        }
        self.entries.push(entry);
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ContentEntry {
    Hash([u8; 32]),
    Content(String),
    EOF([u8; 32]),
}

impl ContentEntry {
    fn dns_size(&self) -> usize {
        1 + match self {
            ContentEntry::Hash(_) | ContentEntry::EOF(_) => 44,
            ContentEntry::Content(data) if data.is_ascii() => data.len(),
            _ => panic!("Non-ASCII characters in base64 output?"),
        }
    }
}

impl ToString for ContentEntry {
    fn to_string(&self) -> String {
        match self {
            ContentEntry::Hash(hash) | ContentEntry::EOF(hash) => base64::encode(hash),
            ContentEntry::Content(data) => data.clone(),
        }
    }
}

pub struct PolysemeBuilder {
    shared_key: Vec<u8>,
    hmac_key: Key,
    counter: u64,
    base64_buffer: Vec<u8>,
    current_chunk: String,
    current_set: ContentSet,
}

pub(crate) fn next_ahotp(counter: &mut u64, shared_key: &Key) -> String {
    let hash = sign(shared_key, counter.to_be_bytes().as_ref());
    *counter += 1;
    base32::encode(base32::Alphabet::Crockford, hash.as_ref()).to_ascii_lowercase()
}

impl PolysemeBuilder {
    pub fn new(shared_key: &[u8]) -> PolysemeBuilder {
        let key = Key::new(HMAC_SHA256, shared_key);
        let mut counter = 0;
        let current_set = ContentSet::new(next_ahotp(&mut counter, &key));

        PolysemeBuilder {
            shared_key: shared_key.to_vec(),
            hmac_key: key,
            counter,
            current_chunk: String::new(),
            base64_buffer: Vec::new(),
            current_set,
        }
    }

    fn next_chunk(&mut self) -> Option<String> {
        if self.current_chunk.len() < 255 {
            return None;
        }

        let (chunk, rest) = self.current_chunk.split_at(255);
        let chunk = chunk.to_string();
        self.current_chunk = rest.to_string();
        Some(chunk)
    }

    fn add_content_entry(&mut self, content_entry: ContentEntry) -> Option<ContentSet> {
        let mut return_val = None;
        if let Err(entry) = self.current_set.add_entry(content_entry) {
            let mut next_set = ContentSet::new(next_ahotp(&mut self.counter, &self.hmac_key));
            next_set
                .add_entry(entry)
                .expect("New record set immediately full? this should not happen");
            self.current_set.calculate_hash();
            return_val = Some(mem::replace(&mut self.current_set, next_set));
        }

        return_val
    }

    fn add_eof(&mut self) -> Option<ContentSet> {
        self.add_content_entry(ContentEntry::EOF(
            digest(&SHA256, &self.shared_key)
                .as_ref()
                .try_into()
                .unwrap(),
        ))
    }

    fn add_chunk(&mut self, chunk: String) -> Option<ContentSet> {
        debug_assert!(
            chunk.len() == 255,
            "Chunk given to PolysemeBuilder::add_chunk should be exactly 255 bytes long"
        );
        self.add_unchecked_chunk(chunk)
    }

    #[inline]
    fn add_unchecked_chunk(&mut self, chunk: String) -> Option<ContentSet> {
        return self.add_content_entry(ContentEntry::Content(chunk));
    }

    pub fn consume(&mut self, input: &[u8]) -> Vec<ContentSet> {
        self.base64_buffer.append(&mut input.to_vec());
        let (to_decode, rest) = self
            .base64_buffer
            .split_at(self.base64_buffer.len() - (self.base64_buffer.len() % 3));
        self.current_chunk += &base64::encode(to_decode);
        self.base64_buffer = rest.to_vec();
        let mut buffer = vec![];
        while let Some(chunk) = self.next_chunk() {
            if let Some(content_set) = self.add_chunk(chunk) {
                buffer.push(content_set)
            }
        }

        buffer
    }

    pub fn finalize(mut self) -> Vec<ContentSet> {
        let mut buffer = vec![];
        self.current_chunk += &base64::encode(&self.base64_buffer);
        let chunk = self.current_chunk.split_off(0);
        if let Some(set) = self.add_unchecked_chunk(chunk) {
            buffer.push(set);
        }

        assert!(
            self.add_eof().is_none(),
            "EOF should only add 1 entry and never overflow the current buffer"
        );
        self.current_set.calculate_hash();
        buffer.push(self.current_set);
        buffer
    }
}

pub fn create_polyseme(shared_key: &[u8], input: &[u8]) -> Vec<ContentSet> {
    let mut builder = PolysemeBuilder::new(shared_key);
    let mut sets = builder.consume(input);
    sets.append(&mut builder.finalize());
    sets
}
