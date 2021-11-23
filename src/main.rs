use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;

mod command;
use command::OutputExt;
mod ips;
use ips::*;
mod contents;

#[derive(Deserialize)]
struct PkgRepoList {
    #[serde(rename = "pkg.fmri")]
    pkg_fmri: String,
}

pub fn pkgrepo_list(repo: &str, pattern: Option<&str>) -> Result<Vec<Package>> {
    let mut cmd = Command::new("/usr/bin/pkgrepo");
    cmd.env_clear();
    cmd.arg("list");
    cmd.arg("-F");
    cmd.arg("json");
    cmd.arg("-s");
    cmd.arg(repo);
    if let Some(pattern) = pattern {
        cmd.arg(pattern);
    }

    let res = cmd.output()?;

    if !res.status.success() {
        bail!("pkgrepo list ({}): {}", repo, res.info());
    }

    let list: Vec<PkgRepoList> = serde_json::from_slice(&res.stdout)?;
    Ok(list
        .iter()
        .map(|prl| Package::parse_fmri(&prl.pkg_fmri))
        .collect::<Result<Vec<_>>>()?)
}

pub fn pkgrepo_contents(repo: &str, package: &Package) -> Result<Vec<Action>> {
    let mut cmd = Command::new("/usr/bin/pkgrepo");
    cmd.env_clear();
    cmd.arg("contents");
    cmd.arg("-m");
    cmd.arg("-s");
    cmd.arg(repo);
    cmd.arg(&package.to_string());

    let res = cmd.output()?;

    if !res.status.success() {
        bail!("pkgrepo contents ({}): {}", repo, res.info());
    }

    let manifest = String::from_utf8(res.stdout)?;
    Ok(parse_manifest(&manifest)?)
}

fn path_to_man(p: &str) -> Result<(String, String)> {
    if !p.starts_with("usr/share/man/") {
        bail!("not a manual path?");
    }

    let p = p.trim_start_matches("usr/share/man/");

    let e = p.split('/').collect::<Vec<_>>();
    if e.len() != 2 || !e[0].starts_with("man") {
        bail!("peculiar {:?}", e);
    }

    let sect = e[0].trim_start_matches("man");
    if !e[1].ends_with(&format!(".{}", sect)) {
        bail!("most peculiar {:?}", e);
    }

    let page = e[1].trim_end_matches(&format!(".{}", sect));
    let sect = sect.to_uppercase();

    Ok((sect.to_string(), page.to_string()))
}

#[derive(Debug, Clone)]
struct Record {
    link: bool,
    sect: String,
    page: String,
    pkg: String,
    orig_sect: Option<String>,
}

#[derive(Default)]
struct Database {
    records: Vec<Record>,
}

impl Database {
    pub fn insert(
        &mut self,
        link: bool,
        sect: &str,
        page: &str,
        pkg: &str,
    ) -> Result<()> {
        let nr = Record {
            link,
            sect: sect.to_string(),
            page: page.to_string(),
            pkg: pkg.to_string(),
            orig_sect: None,
        };

        for r in &self.records {
            if r.sect == nr.sect && r.page == nr.page {
                bail!(
                    "new record {:?} conflicts with existing record {:?}",
                    nr,
                    r
                );
            }
        }

        self.records.push(nr);
        self.records.sort_by(|a, b| match a.sect.cmp(&b.sect) {
            Ordering::Equal => a.page.cmp(&b.page),
            x => x,
        });

        Ok(())
    }

    pub fn load(path: &str) -> Result<Database> {
        let mut f = std::fs::File::open(path)?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        let mut records = Vec::new();
        for l in s.lines() {
            let t = l.split('\t').collect::<Vec<_>>();
            if t.len() != 4 {
                bail!("broken record {:?}", t);
            }

            let link = match t[0] {
                "l" => true,
                "f" => false,
                x => bail!("invalid link field {:?}", t),
            };

            records.push(Record {
                link,
                sect: t[1].to_string(),
                page: t[2].to_string(),
                pkg: t[3].to_string(),
                orig_sect: None,
            });
        }

        Ok(Database { records })
    }

    pub fn lookup(&self, sect: &str, page: &str) -> Option<Record> {
        for r in self.records.iter() {
            if r.page == page && r.sect == sect {
                return Some(r.clone());
            }
        }
        None
    }

    pub fn transform(&self) -> Database {
        let mut out = Vec::new();

        for r in self.records.iter() {
            if r.sect == "1M" {
                out.push(Record {
                    link: r.link,
                    sect: "8".to_string(),
                    page: r.page.to_string(),
                    pkg: r.pkg.to_string(),
                    orig_sect: Some("1M".to_string()),
                });
                continue;
            }

            let mut i = r.sect.chars();
            let s = i.next().unwrap();
            let sub = i.collect::<String>();

            let newsect = match s {
                '4' => {
                    format!("5{}", sub)
                }
                '5' => {
                    format!("7{}", sub)
                }
                '7' => {
                    format!("4{}", sub)
                }
                _ => {
                    out.push(r.clone());
                    continue;
                }
            };

            out.push(Record {
                link: r.link,
                sect: newsect.to_string(),
                orig_sect: Some(r.sect.to_string()),
                page: r.page.to_string(),
                pkg: r.pkg.to_string(),
            });
        }

        out.sort_by(|a, b| match a.sect.cmp(&b.sect) {
            Ordering::Equal => a.page.cmp(&b.page),
            x => x,
        });

        Database { records: out }
    }
}

fn find_xrefs_line(l: &str) -> Result<Vec<(String, String)>> {
    lazy_static! {
        static ref RE2: Regex = Regex::new(
            r#"(?x)
            \\fB
            \\fB
            (?P<page>[a-zA-Z_0-9+.-]+)
            \\fR
            \\fR
            \(
            (?P<sect>[0-9][^\[)]*)
            \)
            "#
        )
        .unwrap();
        static ref RE: Regex = Regex::new(
            r#"(?x)
            \\fB
            (?P<page>[a-zA-Z_0-9+.-]+)
            \\fR
            \(
            (?P<sect>[0-9][^\[)]*)
            \)
            "#
        )
        .unwrap();
    }

    let mut out = Vec::new();

    for m in RE2.captures_iter(l) {
        let m: regex::Captures = m;
        let page = m.name("page").unwrap().as_str();
        let sect = m.name("sect").unwrap().as_str();
        // if page.starts_with("-") {
        //     /*
        //      * Probably a poorly typeset command-line argument.
        //      */
        //     continue;
        // }
        if sect.contains(r#"\fI"#) {
            /*
             * This is probably a poorly typeset function call.
             */
            continue;
        }
        if sect != sect.to_uppercase() {
            eprintln!("sect {:?} is not in uppercase: {:?}", sect, l);
            continue;
        }

        out.push((sect.to_string(), page.to_string()));
    }

    for m in RE.captures_iter(l) {
        let m: regex::Captures = m;
        let page = m.name("page").unwrap().as_str();
        let sect = m.name("sect").unwrap().as_str();
        // if page.starts_with("-") {
        //     /*
        //      * Probably a poorly typeset command-line argument.
        //      */
        //     continue;
        // }
        if sect.contains(r#"\fI"#) {
            /*
             * This is probably a poorly typeset function call.
             */
            continue;
        }
        if sect != sect.to_uppercase() {
            eprintln!("sect {:?} is not in uppercase: {:?}", sect, l);
            continue;
        }

        out.push((sect.to_string(), page.to_string()));
    }

    Ok(out)
}

fn find_xrefs(content: &str) -> Result<Vec<(String, String)>> {
    #[derive(Debug)]
    enum State {
        Rest,
        Copyright,
        Content,
        // Name,
        // Description,
    }

    let mut st = State::Rest;
    let mut out = Vec::new();

    for l in content.lines() {
        match st {
            State::Rest => {
                if l.starts_with(".TH WHOIS")
                    || l.starts_with(".TH HOSTS_ACCESS")
                {
                    /*
                     * WTF.
                     */
                    st = State::Content;
                    continue;
                }

                if l == r#"'\" te"#
                    || l == r#".\""#
                    || l == r#"'\" t"#
                    || l == r#"'\""#
                    || l == r#".\" -*- tab-width: 4 -*-"#
                    || l == r#".\" -*- nroff -*-"#
                    || (l.starts_with(r#".\""#) && l.contains("Copyright"))
                {
                    st = State::Copyright;
                } else {
                    bail!("what? {:?}? {:?}", st, l);
                }
            }
            State::Copyright => {
                if l.starts_with(r#".\""#) || l == "" {
                    continue;
                } else if l.starts_with(".TH") {
                    /*
                     * XXX Check page title?
                     */
                    st = State::Content;
                } else {
                    bail!("what? {:?}? {:?}", st, l);
                }
            }
            State::Content => {
                if l.starts_with(".") {
                    /*
                     * XXX
                     */
                    continue;
                }

                out.extend(find_xrefs_line(l)?);
            }
            //     if l == ".SH NAME" {
            //         st = State::Name;
            //     } else {
            //         bail!("what? {:?}? {:?}", st, l);
            //     }
            // }
            // State::Name => {
            //     if l == ".SH DESCRIPTION" {
            //         st = State::Description;
            //     } else if l.starts_with(".SH") {
            //         bail!("what section? {:?}? {:?}", st, l);
            //     } else {
            //         bail!("what? {:?}? {:?}", st, l);
            //     }
            // }
            _ => {
                bail!("what? {:?}? {:?}", st, l);
            }
        }
    }

    Ok(out)
}

fn main() -> Result<()> {
    let cmd = std::env::args().nth(1).ok_or_else(|| anyhow!("no cmd"))?;

    match cmd.as_str() {
        "kinds" => {
            let db = Database::load("database.txt")?;

            for r in db.records.iter() {
                if r.link {
                    continue;
                }

                let p = PathBuf::from(format!(
                    "/ws/rti/usr/src/man/man{}/{}.{}",
                    r.sect.to_ascii_lowercase(),
                    r.page,
                    r.sect.to_ascii_lowercase()
                ));

                if !p.exists() && r.page.contains("event") && r.sect == "3CPC" {
                    /*
                     * This is probably an autogenerated file.
                     */
                    continue;
                }

                /*
                 * Do we think this is mandoc or not?
                 */
                let mut f = std::fs::File::open(&p)?;
                let mut s = String::new();
                f.read_to_string(&mut s)?;
                if s.lines()
                    .any(|l| l == ".Os" || l.starts_with(".Os illumos"))
                {
                    println!("mdoc {}({})", r.page, r.sect);
                    continue;
                } else {
                    println!("roff {}({})", r.page, r.sect);
                    let xrefs = find_xrefs(&s)
                        .with_context(|| anyhow!("file {:?}", p))?;
                    for xref in &xrefs {
                        //println!("{:?}", xref);
                        if db.lookup(&xref.0, &xref.1).is_none() {
                            eprintln!("MISSING {}({})?", xref.1, xref.0);
                        } else {
                            println!("    -> {}({})", xref.1, xref.0);
                        }
                    }
                }
            }
        }
        "conflicts" => {
            let db = Database::load("database.txt")?;

            let mut conflicts: BTreeMap<String, Vec<String>> = BTreeMap::new();

            for r in db.records.iter() {
                match r.sect.chars().next().unwrap() {
                    '4' | '5' | '7' => {
                        let c =
                            conflicts.entry(r.page.to_string()).or_default();
                        if !c.contains(&r.sect) {
                            c.push(r.sect.to_string());
                        }
                        //println!("{}", r.page);
                    }
                    _ => {}
                }
            }

            for (k, v) in conflicts.iter() {
                if v.len() < 2 {
                    continue;
                }

                let mut out = String::new();
                for v in v {
                    out += &format!("{:<3} ", v);
                }

                println!("{:<16} {}", k, out.trim_end());
            }

            //println!("{:#?}", conflicts);
        }
        "simulate" => {
            let db = Database::load("database.txt")?;
            let newdb = db.transform();

            for r in db.records {
                if let Some(conflict) = newdb.lookup(&r.sect, &r.page) {
                    if conflict.orig_sect.is_none() {
                        continue;
                    }
                    println!("old page {}({}) is obscured", r.page, r.sect);
                }
            }
        }
        "mkdb" => {
            let repo = "/ws/rti/packages/i386/nightly-nd/repo.redist";

            let list = pkgrepo_list(&repo, None)?;

            let w = contents::PkgContents::new();

            for pkg in list {
                w.append(vec![contents::PkgContentsWorkItem {
                    repo: repo.to_string(),
                    pkg,
                }]);
            }

            let mut db = Database::default();

            let rx = w.run(8);
            while let Ok(r) = rx.recv() {
                if r.len() != 1 {
                    bail!("unexpected {:?}", r);
                }
                let p = &r[0];
                eprintln!("{}", p.pkg.name());

                /*
                 * Get the contents and look for manual page files and links.
                 * Build a database that we can emit to a sorted file at the
                 * end.
                 */
                for a in &p.contents {
                    match &a {
                        Action::File(af) => {
                            if af.path().starts_with("usr/man") {
                                bail!("weird? {:?}", af);
                            }
                            if !af.path().starts_with("usr/share/man/") {
                                continue;
                            }

                            let (sect, page) = path_to_man(af.path())?;
                            db.insert(false, &sect, &page, p.pkg.name())?;
                        }
                        Action::Link(al) => {
                            if al.path() != "usr/man"
                                && al.path().starts_with("usr/man")
                            {
                                bail!("weird? {:?}", al);
                            }
                            if !al.path().starts_with("usr/share/man/") {
                                continue;
                            }

                            let (sect, page) = path_to_man(al.path())?;

                            let mut t = al.target();
                            if t.starts_with("../man1/") {
                                t = t.trim_start_matches("../man1/");
                            }
                            if t.starts_with("../../../has/man/man1has/") {
                                t = t.trim_start_matches(
                                    "../../../has/man/man1has/",
                                );
                            }
                            if t.starts_with("./") {
                                t = t.trim_start_matches("./");
                            }
                            if t.contains('/') {
                                bail!("target weird {:?}", al.target());
                            }

                            db.insert(true, &sect, &page, p.pkg.name())?;
                        }
                        _ => {}
                    }
                }
            }

            for rec in db.records {
                let l = if rec.link { "l" } else { "f" };
                println!("{}\t{}\t{}\t{}", l, rec.sect, rec.page, rec.pkg);
            }
        }
        x => {
            bail!("unknown command {:?}", x);
        }
    }

    Ok(())
}
