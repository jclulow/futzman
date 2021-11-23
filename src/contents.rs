use std::sync::mpsc;
use std::thread;
use std::sync::{Mutex, Arc};

use anyhow::Result;

use super::ips::*;
use super::pkgrepo_contents;

pub struct PkgContentsWorkItem {
    pub repo: String,
    pub pkg: Package,
}

pub struct PkgContentsWorkGroup {
    pub group: Vec<PkgContentsWorkItem>,
}

pub struct PkgContents {
    pub q: Arc<Mutex<Vec<PkgContentsWorkGroup>>>,
}

#[derive(Debug)]
pub struct PkgContentsResult {
    #[allow(dead_code)]
    pub repo: String,
    pub pkg: Package,
    pub contents: Vec<Action>,
}

impl PkgContents {
    pub fn new() -> PkgContents {
        PkgContents {
            q: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn append(&self, group: Vec<PkgContentsWorkItem>) {
        self.q.lock().unwrap().push(PkgContentsWorkGroup {
            group,
        });
    }

    pub fn run(self, nthr: usize) -> mpsc::Receiver<Vec<PkgContentsResult>> {
        let (tx, rx) = mpsc::sync_channel::<Vec<PkgContentsResult>>(0);
        thread::Builder::new().name("r".to_string()).spawn(move || {
            let mut threads = (0..nthr).into_iter().map(|n| {
                let q = Arc::clone(&self.q);
                let tx = tx.clone();

                let n = format!("w{:02}", n + 1);
                thread::Builder::new().name(n).spawn(move || {
                    loop {
                        let g = if let Some(g) = q.lock().unwrap().pop() {
                            g
                        } else {
                            break;
                        };

                        let r = g.group.iter().map(|i| {
                            let contents = pkgrepo_contents(&i.repo, &i.pkg)?;
                            Ok(PkgContentsResult {
                                repo: i.repo.clone(),
                                pkg: i.pkg.clone(),
                                contents,
                            })
                        }).collect::<Result<Vec<_>>>();

                        match r {
                            Ok(r) => tx.send(r).unwrap(),
                            Err(e) => {
                                /*
                                 * Bring the whole process down if we hit an IPS
                                 * error:
                                 */
                                eprintln!("ERROR: {:?}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                }).unwrap()
            }).collect::<Vec<_>>();

            drop(tx);

            while let Some(t) = threads.pop() {
                t.join().expect("join");
            }
        }).unwrap();
        rx
    }
}
