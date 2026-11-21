//! IP → owner (ASN name) and IP → country, from sorted range files loaded in memory.
//! IPv4 and IPv6 live in separate tables so 700k IPv4 rows cost 12 bytes each, not 36.

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    net::IpAddr,
    path::Path,
};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;

struct Table<K> {
    starts: Vec<K>,
    ends: Vec<K>,
    vals: Vec<u32>,
}

impl<K: Ord + Copy> Table<K> {
    fn new() -> Self {
        Self {
            starts: Vec::new(),
            ends: Vec::new(),
            vals: Vec::new(),
        }
    }

    fn get(&self, k: K) -> Option<u32> {
        let i = self.starts.partition_point(|s| *s <= k).checked_sub(1)?;
        (k <= self.ends[i]).then(|| self.vals[i])
    }
}

pub struct Ranges {
    v4: Table<u32>,
    v6: Table<u128>,
    names: Vec<String>,
}

fn key(ip: IpAddr) -> Result<u32, u128> {
    match ip.to_canonical() {
        IpAddr::V4(a) => Ok(a.into()),
        IpAddr::V6(a) => Err(a.into()),
    }
}

impl Ranges {
    /// `split` turns one line into (first ip, last ip, label); None skips the line.
    pub fn from_lines(
        lines: impl Iterator<Item = String>,
        split: impl Fn(&str) -> Option<(&str, &str, &str)>,
    ) -> Result<Self> {
        let mut r = Ranges {
            v4: Table::new(),
            v6: Table::new(),
            names: Vec::new(),
        };
        let mut ids: HashMap<String, u32> = HashMap::new();
        for line in lines {
            let Some((a, b, label)) = split(&line) else {
                continue;
            };
            let (Ok(a), Ok(b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>()) else {
                continue;
            };
            let id = *ids.entry(label.to_owned()).or_insert_with(|| {
                r.names.push(label.to_owned());
                (r.names.len() - 1) as u32
            });
            match (key(a), key(b)) {
                (Ok(a), Ok(b)) => push(&mut r.v4, a, b, id),
                (Err(a), Err(b)) => push(&mut r.v6, a, b, id),
                _ => continue,
            }
        }
        // Binary search is only correct on sorted, non-overlapping ranges.
        if !r.v4.starts.is_sorted() || !r.v6.starts.is_sorted() {
            bail!("ranges are not sorted");
        }
        Ok(r)
    }

    pub fn get(&self, ip: IpAddr) -> Option<&str> {
        let id = match key(ip) {
            Ok(k) => self.v4.get(k),
            Err(k) => self.v6.get(k),
        }?;
        Some(&self.names[id as usize])
    }
}

fn push<K>(t: &mut Table<K>, a: K, b: K, id: u32) {
    t.starts.push(a);
    t.ends.push(b);
    t.vals.push(id);
}

fn gz_lines(path: &Path) -> Result<impl Iterator<Item = String>> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    Ok(BufReader::new(GzDecoder::new(f))
        .lines()
        .map_while(Result::ok))
}

/// DB-IP Lite country CSV (CC BY 4.0): `first,last,CC`.
pub fn countries(path: &Path) -> Result<Ranges> {
    Ranges::from_lines(gz_lines(path)?, |l| {
        let mut it = l.split(',');
        let row = (it.next()?, it.next()?, it.next()?);
        (row.2 != "ZZ").then_some(row) // ZZ = reserved / unknown
    })
}

/// iptoasn.com combined TSV (PDDL): `first\tlast\tasn\tcc\tdescription`; ASN 0 = not routed.
pub fn owners(path: &Path) -> Result<Ranges> {
    Ranges::from_lines(gz_lines(path)?, |l| {
        let mut it = l.split('\t');
        let (a, b, asn) = (it.next()?, it.next()?, it.next()?);
        let desc = it.nth(1)?;
        (asn != "0").then_some((a, b, desc))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Ranges {
        let rows =
            "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n2001:db8::,2001:db8::ffff,ZZ\nbad,line,XX";
        Ranges::from_lines(rows.lines().map(String::from), |l| {
            let mut it = l.split(',');
            Some((it.next()?, it.next()?, it.next()?))
        })
        .unwrap()
    }

    #[test]
    fn lookups_hit_edges_and_miss_gaps() {
        let t = table();
        let get = |s: &str| t.get(s.parse().unwrap());
        assert_eq!(get("1.0.0.0"), Some("AU"));
        assert_eq!(get("1.0.0.255"), Some("AU"));
        assert_eq!(get("1.0.3.255"), Some("CN"));
        assert_eq!(get("1.0.4.0"), None);
        assert_eq!(get("0.255.255.255"), None);
        assert_eq!(get("2001:db8::1"), Some("ZZ"));
        assert_eq!(get("::ffff:1.0.1.5"), Some("CN"));
    }

    #[test]
    fn unsorted_input_is_refused() {
        let rows = "2.0.0.0,2.0.0.1,B\n1.0.0.0,1.0.0.1,A";
        let r = Ranges::from_lines(rows.lines().map(String::from), |l| {
            let mut it = l.split(',');
            Some((it.next()?, it.next()?, it.next()?))
        });
        assert!(r.is_err());
    }
}
