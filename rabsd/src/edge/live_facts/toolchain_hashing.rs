//! Bounded parallel hashing for a cold, fully observed toolchain.
//!
//! The background warm remains the owner. One optional scoped helper is shared
//! across ALL toolchain warms in the process; contention or thread-start failure
//! falls back to the owner's thread, never a queue or detached work. Large files
//! start first, but results retain the original canonical order. Hardlinked
//! aliases share a read only while their complete observed identities agree.
//! Every pathname is revalidated, including aliases that did not supply a read.

use super::{FileSig, ToolchainInputs, digest_stable_at, lstat_regular};
use rabs_protocol::result_identity::TypedDigest;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const PARALLEL_BYTES: u64 = 4 * 1024 * 1024;
static HELPER_BUSY: AtomicBool = AtomicBool::new(false);

/// This is an execution-capacity permit, not an input or serving witness.
struct HelperPermit<'a>(&'a AtomicBool);

impl<'a> HelperPermit<'a> {
    fn acquire(busy: &'a AtomicBool) -> Option<Self> {
        busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self(busy))
    }
}

impl Drop for HelperPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) struct ToolchainDigests {
    pub(super) compiler: TypedDigest,
    pub(super) runtime: Vec<TypedDigest>,
    pub(super) sysroot: Vec<TypedDigest>,
}

pub(super) fn hash(inputs: &ToolchainInputs) -> Result<ToolchainDigests, String> {
    let files: Vec<_> = std::iter::once(&inputs.compiler)
        .chain(&inputs.runtime_libraries)
        .chain(&inputs.sysroot_files)
        .map(|(path, sig)| (path.as_path(), *sig))
        .collect();
    let mut digests = hash_files(&files, &HELPER_BUSY, |path, sig| {
        digest_stable_at(path, sig).map(|(_, digest)| digest)
    })
    .map_err(|error| format!("hash toolchain: {error}"))?;
    let sysroot = digests.split_off(1 + inputs.runtime_libraries.len());
    let runtime = digests.split_off(1);
    let compiler = digests
        .pop()
        .ok_or_else(|| "toolchain capture lost the compiler digest".to_owned())?;
    Ok(ToolchainDigests {
        compiler,
        runtime,
        sysroot,
    })
}

fn verify_files(files: &[(&Path, FileSig)]) -> io::Result<()> {
    for (path, expected) in files {
        if lstat_regular(path)? != *expected {
            return Err(io::Error::other(format!(
                "toolchain input {} changed during hashing",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hash_files(
    files: &[(&Path, FileSig)],
    helper_busy: &AtomicBool,
    hash: impl Fn(&Path, FileSig) -> io::Result<TypedDigest> + Sync,
) -> io::Result<Vec<TypedDigest>> {
    verify_files(files)?;
    let mut identities = HashMap::new();
    let mut jobs = Vec::new();
    let mut positions = Vec::with_capacity(files.len());
    for &(path, sig) in files {
        let next = jobs.len();
        let index = *identities.entry(sig).or_insert_with(|| {
            jobs.push((path, sig));
            next
        });
        positions.push(index);
    }
    let total = jobs
        .iter()
        .fold(0_u64, |sum, (_, sig)| sum.saturating_add(sig.size()));
    let digests = hash_jobs(&jobs, helper_busy, total >= PARALLEL_BYTES, &hash)?;
    // Coalescing must not hide a replaced or retargeted alias. Directory
    // generations are additionally checked by the owning ToolchainInputs.
    verify_files(files)?;
    Ok(positions
        .into_iter()
        .map(|index| digests[index].clone())
        .collect())
}

fn hash_jobs(
    jobs: &[(&Path, FileSig)],
    helper_busy: &AtomicBool,
    parallel: bool,
    hash: &(impl Fn(&Path, FileSig) -> io::Result<TypedDigest> + Sync),
) -> io::Result<Vec<TypedDigest>> {
    let mut order: Vec<_> = (0..jobs.len()).collect();
    order.sort_by_key(|&index| (std::cmp::Reverse(jobs[index].1.size()), index));
    let next = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    let run = || {
        // A panic with unwinding enabled is a failed warm, not a permanently
        // occupied Slot::Warming. Abort-mode panics still terminate the process.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut complete = Vec::new();
            while !stopped.load(Ordering::Acquire) {
                let Some(&index) = order.get(next.fetch_add(1, Ordering::Relaxed)) else {
                    break;
                };
                let (path, sig) = jobs[index];
                complete.push((index, hash(path, sig)?));
            }
            Ok::<_, io::Error>(complete)
        }))
        .unwrap_or_else(|_| Err(io::Error::other("toolchain digest worker panicked")));
        if result.is_err() {
            stopped.store(true, Ordering::Release);
        }
        result
    };
    let complete = std::thread::scope(|scope| {
        let helper = if parallel && jobs.len() > 1 {
            HelperPermit::acquire(helper_busy).and_then(|permit| {
                let run = &run;
                std::thread::Builder::new()
                    .name("rabs-toolchain-hash".into())
                    .spawn_scoped(scope, move || {
                        let _permit = permit;
                        run()
                    })
                    .ok()
            })
        } else {
            None
        };
        let owner = run();
        // Join BEFORE propagating either failure. No reader outlives the warm,
        // including on helper errors, owner errors, or an unwinding hasher.
        let other = helper.map_or_else(
            || Ok(Vec::new()),
            |helper| {
                helper.join().unwrap_or_else(|_| {
                    Err(io::Error::other("toolchain digest helper panicked"))
                })
            },
        );
        let mut complete = owner?;
        complete.extend(other?);
        Ok::<_, io::Error>(complete)
    })?;
    let mut ordered: Vec<Option<TypedDigest>> = vec![None; jobs.len()];
    for (index, digest) in complete {
        ordered[index] = Some(digest);
    }
    ordered
        .into_iter()
        .map(|digest| {
            digest.ok_or_else(|| io::Error::other("incomplete toolchain digest batch"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    fn fixture() -> (tempfile::TempDir, Vec<std::path::PathBuf>) {
        let dir = crate::test_util::private_tempdir();
        let paths: Vec<_> = ["small", "large", "empty"]
            .iter()
            .map(|name| dir.path().join(name))
            .collect();
        std::fs::write(&paths[0], b"small\0\xff").unwrap();
        std::fs::write(&paths[1], vec![137; 512 * 1024 + 17]).unwrap();
        std::fs::write(&paths[2], b"").unwrap();
        (dir, paths)
    }

    fn observed(paths: &[std::path::PathBuf]) -> Vec<(&Path, FileSig)> {
        paths
            .iter()
            .map(|path| (path.as_path(), lstat_regular(path).unwrap()))
            .collect()
    }

    fn digest(path: &Path, sig: FileSig) -> io::Result<TypedDigest> {
        digest_stable_at(path, sig).map(|(_, digest)| digest)
    }

    #[test]
    fn parallel_and_serial_reads_keep_original_order_and_exact_content_identity() {
        let (_dir, paths) = fixture();
        let jobs = observed(&paths);
        let busy = AtomicBool::new(false);
        let expected: Vec<_> = jobs
            .iter()
            .map(|&(p, s)| digest(p, s).unwrap())
            .collect();
        assert_eq!(hash_jobs(&jobs, &busy, false, &digest).unwrap(), expected);
        assert_eq!(hash_jobs(&jobs, &busy, true, &digest).unwrap(), expected);
        assert!(!busy.load(Ordering::Acquire));
    }

    #[test]
    fn largest_files_start_first_without_changing_canonical_positions() {
        let (_dir, paths) = fixture();
        let jobs = observed(&paths);
        let started = Mutex::new(Vec::new());
        hash_jobs(&jobs, &AtomicBool::new(false), false, &|path, sig| {
            started.lock().unwrap().push(path.to_path_buf());
            digest(path, sig)
        })
        .unwrap();
        assert_eq!(
            *started.lock().unwrap(),
            [paths[1].clone(), paths[0].clone(), paths[2].clone()]
        );
    }

    #[test]
    fn two_readers_overlap_and_are_joined_before_return() {
        let (_dir, paths) = fixture();
        let jobs = observed(&paths[..2]);
        let gate = (Mutex::new(0), Condvar::new());
        let active = AtomicUsize::new(0);
        let busy = AtomicBool::new(false);
        let result = hash_jobs(&jobs, &busy, true, &|path, sig| {
            active.fetch_add(1, Ordering::SeqCst);
            let mut entered = gate.0.lock().unwrap();
            *entered += 1;
            gate.1.notify_all();
            let (entered, _) = gate
                .1
                .wait_timeout_while(entered, Duration::from_secs(5), |entered| *entered < 2)
                .unwrap();
            let both = *entered == 2;
            drop(entered);
            let result = if both {
                digest(path, sig)
            } else {
                Err(io::Error::other("second digest reader never entered"))
            };
            active.fetch_sub(1, Ordering::SeqCst);
            result
        });
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(!busy.load(Ordering::Acquire));
    }

    #[test]
    fn occupied_helper_falls_back_without_releasing_another_warms_permit() {
        let (_dir, paths) = fixture();
        let jobs = observed(&paths);
        let busy = AtomicBool::new(false);
        let permit = HelperPermit::acquire(&busy).unwrap();
        let owner = std::thread::current().id();
        let actual = hash_jobs(&jobs, &busy, true, &|path, sig| {
            assert_eq!(std::thread::current().id(), owner);
            digest(path, sig)
        })
        .unwrap();
        assert_eq!(actual.len(), 3);
        assert!(busy.load(Ordering::Acquire));
        drop(permit);
        assert!(!busy.load(Ordering::Acquire));
    }

    #[test]
    fn hardlinks_share_one_read_but_not_path_validation() {
        let (dir, mut paths) = fixture();
        let alias = dir.path().join("alias");
        std::fs::hard_link(&paths[0], &alias).unwrap();
        paths.push(alias.clone());
        let files = observed(&paths);
        let calls = AtomicUsize::new(0);
        let actual = hash_files(&files, &AtomicBool::new(false), |path, sig| {
            calls.fetch_add(1, Ordering::Relaxed);
            digest(path, sig)
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert_eq!(actual[0], actual[3]);
        // Replace just the alias during another read: a coalesced path is
        // still mandatory evidence even though it did not supply any bytes.
        let result = hash_files(&files, &AtomicBool::new(false), |path, sig| {
            let result = digest(path, sig);
            if path == paths[2].as_path() {
                std::fs::rename(&alias, dir.path().join("retained-alias")).unwrap();
                std::fs::write(&alias, b"other").unwrap();
            }
            result
        });
        assert!(result.is_err());
    }

    #[test]
    fn replaced_and_symlinked_inputs_refuse_before_any_read() {
        let (dir, paths) = fixture();
        let files = observed(&paths);
        std::fs::rename(&paths[0], dir.path().join("retained-small")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("retained-small"), &paths[0]).unwrap();
        let calls = AtomicUsize::new(0);
        assert!(
            hash_files(&files, &AtomicBool::new(false), |path, sig| {
                calls.fetch_add(1, Ordering::Relaxed);
                digest(path, sig)
            })
            .is_err()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn errors_and_unwinding_hashers_release_capacity_and_never_return_a_partial_batch() {
        let (_dir, paths) = fixture();
        let jobs = observed(&paths);
        for panic in [false, true] {
            let busy = AtomicBool::new(false);
            let result = hash_jobs(&jobs, &busy, true, &|_, _| {
                assert!(!panic, "injected digest unwind");
                Err(io::Error::other("injected digest read failure"))
            });
            assert!(result.is_err());
            assert!(!busy.load(Ordering::Acquire));
            assert!(hash_jobs(&jobs, &busy, true, &digest).is_ok());
        }
    }

    #[test]
    fn typed_batch_keeps_compiler_runtime_and_sysroot_roles() {
        let (_dir, paths) = fixture();
        let files = observed(&paths);
        let inputs = ToolchainInputs {
            compiler: (paths[0].clone(), files[0].1),
            runtime_libraries: vec![(paths[1].clone(), files[1].1)],
            sysroot_files: vec![
                (paths[2].clone(), files[2].1),
                (paths[1].clone(), files[1].1),
            ],
            directories: Vec::new(),
        };
        let actual = hash(&inputs).unwrap();
        assert_eq!(actual.compiler, digest(files[0].0, files[0].1).unwrap());
        assert_eq!(actual.runtime, vec![digest(files[1].0, files[1].1).unwrap()]);
        assert_eq!(
            actual.sysroot,
            vec![
                digest(files[2].0, files[2].1).unwrap(),
                digest(files[1].0, files[1].1).unwrap(),
            ]
        );
    }

    #[test]
    fn a_failed_read_waits_for_the_other_owned_reader_to_finish() {
        let (_dir, paths) = fixture();
        let gate = (Mutex::new((false, false)), Condvar::new());
        let busy = AtomicBool::new(false);
        let (failed_tx, failed_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let jobs = observed(&paths[..2]);
                let result = hash_jobs(&jobs, &busy, true, &|path, sig| {
                    let state = gate.0.lock().unwrap();
                    if path == paths[1].as_path() {
                        let mut state = state;
                        state.0 = true;
                        gate.1.notify_all();
                        let (state, _) = gate
                            .1
                            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.1)
                            .unwrap();
                        let released = state.1;
                        drop(state);
                        if !released {
                            return Err(io::Error::other("test reader was not released"));
                        }
                        digest(path, sig)
                    } else {
                        let (state, _) = gate
                            .1
                            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.0)
                            .unwrap();
                        drop(state);
                        failed_tx.send(()).unwrap();
                        Err(io::Error::other("failed while another reader owns work"))
                    }
                });
                done_tx.send(result.is_err()).unwrap();
            });
            failed_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let early = done_rx.recv_timeout(Duration::from_millis(50));
            // Release and join before assertions, also against an implementation
            // that incorrectly returned on the first failure.
            gate.0.lock().unwrap().1 = true;
            gate.1.notify_all();
            reader.join().unwrap();
            assert!(matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)));
            assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        });
        assert!(!busy.load(Ordering::Acquire));
    }
}
