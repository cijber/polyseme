use clap::{App, Arg};
use polyseme::{PolysemeBuilder, PolysemeParser, RecordFetcher};
use std::io::Stdout;
use std::io::{stdout, Write};
use std::net::IpAddr;
use std::str::FromStr;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

fn main() {
    let app = App::new("Polyseme Fetch")
        .version("1.0.0")
        .arg(
            Arg::with_name("dns")
                .long("dns")
                .value_name("DNS_SERVER")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("DNS_PORT")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("shared-key")
                .required(true)
                .takes_value(true),
        )
        .arg(Arg::with_name("domain").required(true).takes_value(true));

    let matches = app.get_matches();

    let resolver = if let Some(item) = matches.value_of("dns") {
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(
                &[IpAddr::from_str(item).unwrap()],
                matches.value_of("port").unwrap_or("53").parse().unwrap(),
            ),
        );
        Resolver::new(config, ResolverOpts::default()).unwrap()
    } else {
        Resolver::from_system_conf().unwrap()
    };

    let fetcher = DNSRecordFetcher {
        resolver,
        domain: matches.value_of("domain").unwrap().to_string(),
    };

    let mut parser = PolysemeParser::new(
        matches.value_of("shared-key").unwrap().as_bytes(),
        Box::new(fetcher),
    );

    let mut stdout = stdout();

    while let Some(data) = parser.read().unwrap() {
        stdout.write_all(&data);
    }
}

struct DNSRecordFetcher {
    resolver: Resolver,
    domain: String,
}

impl RecordFetcher for DNSRecordFetcher {
    fn record(&self, name: &str) -> Vec<String> {
        let data = self
            .resolver
            .txt_lookup(&format!("{}.{}", name, self.domain))
            .unwrap();
        let item = if let Some(item) = data.iter().next() {
            item.clone()
        } else {
            return vec![];
        };

        item.iter()
            .map(|str| String::from_utf8_lossy(str).to_string())
            .collect()
    }
}
