use rand::{Rng, distr::Alphanumeric};
use std::borrow::Cow;
use std::path::PathBuf;

pub struct TempPathBuilder<'a> {
    parent: PathBuf,
    length: usize,
    charset: Box<dyn FnMut() -> char + 'a>,
    prefix: Cow<'a, str>,
    suffix: Cow<'a, str>,
}

impl<'a> Default for TempPathBuilder<'a> {
    fn default() -> Self {
        Self {
            parent: std::env::temp_dir(),
            length: 12,
            charset: Box::new(|| rand::rng().sample(Alphanumeric) as char),
            prefix: Cow::Borrowed(""),
            suffix: Cow::Borrowed(""),
        }
    }
}

#[allow(dead_code)]
impl<'a> TempPathBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parent<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.parent = path.into();
        self
    }

    pub fn length(mut self, len: usize) -> Self {
        self.length = len;
        self
    }

    pub fn prefix<S: Into<Cow<'a, str>>>(mut self, pre: S) -> Self {
        self.prefix = pre.into();
        self
    }

    pub fn suffix<S: Into<Cow<'a, str>>>(mut self, suf: S) -> Self {
        self.suffix = suf.into();
        self
    }

    pub fn charset<F: FnMut() -> char + 'a>(mut self, charset_gen: F) -> Self {
        self.charset = Box::new(charset_gen);
        self
    }

    pub fn build(mut self) -> PathBuf {
        loop {
            let random_part = (0..self.length)
                .map(|_| (self.charset)())
                .collect::<String>();

            let filename = format!("{}{}{}", self.prefix, random_part, self.suffix);
            let candidate = self.parent.join(filename);

            if !candidate.exists() {
                return candidate;
            }
        }
    }
}
