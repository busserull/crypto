use std::fmt;

#[derive(Debug)]
pub struct KeyValue(Vec<(String, String)>);

impl KeyValue {
    pub fn from(input: &[(&str, &str)]) -> Self {
        Self(
            input
                .into_iter()
                .map(|(k, v)| (String::from(*k), String::from(*v)))
                .collect(),
        )
    }

    pub fn parse(input: &str) -> Self {
        let mut vec = Vec::new();
        let mut pairs = input.split(['&', '=']);

        while let (Some(k), Some(v)) = (pairs.next(), pairs.next()) {
            vec.push((String::from(k), String::from(v)));
        }

        Self(vec)
    }
}

impl fmt::Display for KeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut pairs = self.0.iter().peekable();

        while let Some((k, v)) = pairs.next() {
            write!(f, "{}={}", k, v)?;

            if pairs.peek().is_some() {
                write!(f, "&")?;
            }
        }

        Ok(())
    }
}
