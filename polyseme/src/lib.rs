mod polyseme_builder;
mod polyseme_parser;

pub use polyseme_builder::*;
pub use polyseme_parser::*;

#[cfg(test)]
mod tests {
    use crate::{create_polyseme, fetch_polyseme};
    use std::collections::HashMap;

    #[test]
    fn test_it_ok() {
        let key = b"this is a key";
        let data = b"y".repeat(10001);

        let poly = create_polyseme(key, &data);
        let poly = poly
            .into_iter()
            .map(|set| (set.name.clone(), set))
            .collect::<HashMap<_, _>>();
        let output = fetch_polyseme(key, poly).unwrap();

        assert_eq!(&output[..], &data[..])
    }
}
