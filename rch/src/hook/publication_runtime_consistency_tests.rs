//! A failed replay cannot let a stale scoped publisher replace durable progress.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};

#[tokio::test(flavor = "current_thread")]
async fn panic_with_failed_replay_cannot_remigrate_or_forget_committed_progress() {
    let _guard = test_guard!();
    for boundary in [
        PublicationPoint::PendingDurable,
        PublicationPoint::PublishedDurable,
    ] {
        let (directory, mut session) = docs(3);
        let writer = session.writer.clone();
        let retained = directory.path().join("retained-publication-log");
        let displaced = Arc::new(Mutex::new(None::<PathBuf>));
        let displaced_by_worker = Arc::clone(&displaced);
        let retained_by_worker = retained.clone();
        let error = session
            .publish_with_observer("docs", move |point, _| {
                if point == boundary {
                    let lease = writer.snapshot();
                    let recipe = lease.recovery.context("missing publication recipe")?;
                    let name = recipe["phases"][0]["publication_journal"]["name"]
                        .as_str()
                        .context("missing publication journal name")?;
                    let original = writer.path.parent().unwrap().join(name);
                    std::fs::rename(&original, &retained_by_worker)?;
                    *displaced_by_worker.lock().unwrap() = Some(original);
                    panic!("interrupt publication and make its panic replay unavailable");
                }
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reload acknowledged publication state after worker panic"),
            "{error:#}"
        );
        // The panic bypassed the worker's normal return, and replay failed.
        // This deliberately retains the caller's pre-migration cached recipe.
        assert!(session.recipe.phases[0].publication_journal.is_none());
        let named = displaced.lock().unwrap().clone().unwrap();
        let retained_bytes = std::fs::read(&retained).unwrap();
        let lease_bytes = std::fs::read(&session.writer.path).unwrap();
        let snapshot = session.writer.snapshot();
        assert!(
            snapshot.recovery.as_ref().unwrap()["phases"][0]
                .get("publication_journal")
                .is_some()
        );
        let entries = std::fs::read_dir(session.writer.path.parent().unwrap())
            .unwrap()
            .count();
        let destination = session.recipe.phases[0].local.join(relative(0));
        let owned_output = if boundary == PublicationPoint::PendingDurable {
            destination
                .parent()
                .unwrap()
                .join(format!(".rch-return-{}", session.recipe.identity))
        } else {
            destination.clone()
        };
        let output_inode = std::fs::metadata(&owned_output).unwrap().ino();
        let callbacks = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&callbacks);
        assert!(
            session
                .publish_with_observer("docs", move |_, _| {
                    observed.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
                .await
                .is_err()
        );
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(session.writer.snapshot(), snapshot);
        assert_eq!(std::fs::read(&session.writer.path).unwrap(), lease_bytes);
        assert_eq!(std::fs::read(&retained).unwrap(), retained_bytes);
        assert_eq!(std::fs::metadata(&owned_output).unwrap().ino(), output_inode);
        assert_eq!(
            std::fs::read_dir(session.writer.path.parent().unwrap())
                .unwrap()
                .count(),
            entries,
            "failed replay created a replacement publication generation"
        );
        assert!(!named.exists());
        // Restore the exact original inode. The same borrowed session may now
        // adopt its durable intent/commit and finish without rewriting it.
        std::fs::rename(&retained, &named).unwrap();
        session.publish("docs").await.unwrap();
        assert_docs(&session, 3);
        assert_eq!(std::fs::metadata(destination).unwrap().ino(), output_inode);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn progress_reload_refuses_changed_output_roots_before_any_publication() {
    let _guard = test_guard!();
    let (directory, mut session) = docs(2);
    session
        .publish_with_observer("docs", |point, _| {
            anyhow::ensure!(
                point != PublicationPoint::PendingDurable,
                "retain pending output"
            );
            Ok(())
        })
        .await
        .unwrap_err();
    let original = session.recipe.phases[0].local.clone();
    let foreign = directory.path().join("uncommitted-output-root");
    std::fs::create_dir(&foreign).unwrap();
    session.recipe.phases[0].local = foreign.clone();
    let lease_bytes = std::fs::read(&session.writer.path).unwrap();
    let callbacks = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&callbacks);
    let error = session
        .publish_with_observer("docs", move |_, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("changed outside its durable progress"),
        "{error:#}"
    );
    assert_eq!(callbacks.load(Ordering::Relaxed), 0);
    assert_eq!(session.recipe.phases[0].local, foreign);
    assert!(!foreign.join("doc").exists());
    assert!(!original.join(relative(0)).exists());
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), lease_bytes);
    session.recipe.phases[0].local = original;
    session.publish("docs").await.unwrap();
    assert_docs(&session, 2);
}
