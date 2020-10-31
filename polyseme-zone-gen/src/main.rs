use clap::{App, Arg};
use polyseme::{ContentSet, PolysemeBuilder};
use std::env::args;
use std::fs::File;
use std::io;
use std::io::{stdin, Read};
use std::process::exit;

fn main() -> io::Result<()> {
    let app = App::new("Polyseme Zone Generator")
        .version("1.0.0")
        .arg(
            Arg::with_name("shared-key")
                .value_name("SHARED_KEY")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("domain")
                .value_name("DOMAIN")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("input")
                .default_value("-")
                .long("input")
                .takes_value(true),
        );

    let matches = app.get_matches();
    let domain = matches.value_of("domain").unwrap();

    let mut input: Box<dyn Read> = if matches.value_of("input").unwrap_or("-") == "-" {
        Box::new(stdin())
    } else {
        Box::new(File::open(matches.value_of("input").unwrap()).expect("Failed to open file"))
    };

    let mut builder = PolysemeBuilder::new(matches.value_of("shared-key").unwrap().as_bytes());
    let mut buffer = vec![0u8; 4096];
    loop {
        let amount = input.read(&mut buffer)?;
        if amount == 0 {
            break;
        }

        write_content_sets(builder.consume(&buffer[..amount]), domain);
    }

    write_content_sets(builder.finalize(), domain);

    Ok(())
}

fn write_content_sets(sets: Vec<ContentSet>, postfix: &str) {
    for item in sets {
        print!("{}.{} TXT", item.name, postfix);
        for entry in item.entries {
            print!(" \"{}\"", entry.to_string());
        }
        print!("\n");
    }
}
