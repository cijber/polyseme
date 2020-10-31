# Polyseme

An implementation of "HOTP Indexed DNS" as conceptualized by munin written in Rust

# `polyseme`

A Rust implementation of HOTP Indexed DNS

# `polyseme-zone-gen`

```
USAGE:
    polyseme-zone-gen <SHARED_KEY> <DOMAIN> --input <input>
```

Used to generates the TXT records in the Zone file format, the output is NOT a valid zone file.  
Do note that `<DOMAIN>` is merely used as postfix for the record names.

If you use a zone file for e.g. `polyseme.example` and would like to upload it to `hello.polyseme.example` you should set `<DOMAIN>` to `hello`

Example usage:

```
$ polyseme-zone-gen "this is not a rickroll" "rickroll" --input ./rickroll.mp4 > rickroll.zone
```

If no input is given STDIN is used

# `polyseme-fetch`

Used to fetch a file hosted via polyseme

```
USAGE:
    polyseme-fetch [OPTIONS] <shared-key> <domain>
```

Example usage:

```
# This is a currently live and accessible server serving a MP4 over DNS
polyseme-fetch "why" "usuck.polyseme.eater.me" > u-suck.mp4
```

## Implementation of Polyseme's HOTP Indexed DNS

Input file is base64 encoded and consumed in 255 byte size parts

Chunk name is generated by _BASE32(HMAC-SHA256(shared-key, counter))_  
For every new chunk counter is incremented by 1

A chunk is a set of parts prefixed with a part containing a SHA256 of all other parts in the chunk.
A chunk has a max size of 65_535 including length prefixes which all take a single byte.  
When adding a part would grow the chunk above the max size, a new chunk should be started. 

EOF is signaled by a part with a SHA256 of the shared-key.