//! Full publisher coverage for compact leases and append-only recovery.

use super::*;
use std::io::Write;

fn journal_path(session: &RecoverySession) -> PathBuf {
    let reference = serde_json::to_value(
        session.recipe.phases[0]
            .publication_journal
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    session
        .writer
        .path
        .parent()
        .unwrap()
        .join(reference["name"].as_str().unwrap())
}

#[tokio::test(flavor = "current_thread")]
async fn every_output_checkpoint_and_heartbeat_keeps_the_same_compact_recipe() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(128);
    let writer = session.writer.clone();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&count);
    session
        .publish_with_observer("docs", {
            let mut recipe = None;
            let mut lease_bytes = None;
            move |point, _| {
                if !matches!(
                    point,
                    PublicationPoint::PendingDurable | PublicationPoint::PublishedDurable
                ) {
                    return Ok(());
                }
                let current = writer.snapshot().recovery.unwrap();
                let phase = &current["phases"][0];
                assert!(phase["publication_journal"].is_object());
                for field in ["baseline", "published", "pending"] {
                    assert!(phase.get(field).is_none(), "inline field retained: {field}");
                }
                if let Some(previous) = &recipe {
                    assert_eq!(&current, previous);
                } else {
                    recipe = Some(current.clone());
                }
                let bytes = std::fs::read(&writer.path)?;
                if let Some(previous) = &lease_bytes {
                    assert_eq!(&bytes, previous, "per-output lease rewrite");
                }
                lease_bytes = Some(bytes);
                let count = observed.fetch_add(1, Ordering::Relaxed) + 1;
                if count.is_multiple_of(32) {
                    writer.heartbeat("sync_down")?;
                    assert_eq!(writer.snapshot().recovery.as_ref(), recipe.as_ref());
                    lease_bytes = Some(std::fs::read(&writer.path)?);
                }
                Ok(())
            }
        })
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 256);
    assert_docs(&session, 128);
    assert!(session.recipe.phases[0].baseline.is_empty());
    let mut recovered = reload(&session);
    recovered.returned(0).unwrap();
    assert_acknowledged(&recovered);
}

#[tokio::test(flavor = "current_thread")]
async fn torn_tail_forks_before_resuming_the_exact_pending_predecessor() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(3);
    let destination = session.recipe.phases[0].local.join(relative(0));
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, b"original predecessor").unwrap();
    assert!(
        session
            .publish_with_observer("docs", |point, _| {
                anyhow::ensure!(point != PublicationPoint::PendingDurable, "stop at intent");
                Ok(())
            })
            .await
            .is_err()
    );
    let original = journal_path(&session);
    let prior = blake3::hash(b"original predecessor").to_hex().to_string();
    assert_eq!(
        session.recipe.phases[0].baseline.get(&relative(0)),
        Some(&prior)
    );
    let mut log = std::fs::OpenOptions::new()
        .append(true)
        .open(&original)
        .unwrap();
    // A power loss in the next frame header must preserve the committed
    // prefix and its original intent, without truncating retained evidence.
    log.write_all(&[0, 0]).unwrap();
    log.sync_all().unwrap();
    drop(log);
    let retained = std::fs::read(&original).unwrap();
    let mut recovered = reload(&session);
    assert_eq!(
        recovered.recipe.phases[0].baseline.get(&relative(0)),
        Some(&prior)
    );
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"original predecessor"
    );
    recovered.publish("docs").await.unwrap();
    assert_ne!(journal_path(&recovered), original);
    assert_eq!(std::fs::read(&original).unwrap(), retained);
    assert_docs(&recovered, 3);
}

#[tokio::test(flavor = "current_thread")]
async fn durable_seal_recovers_a_lost_final_lease_write_without_republication() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(3);
    assert!(
        session
            .publish_with_observer("docs", {
                let mut published = 0;
                move |point, _| {
                    if point == PublicationPoint::PublishedDurable {
                        published += 1;
                        anyhow::ensure!(published != 3, "stop before terminal lease write");
                    }
                    Ok(())
                }
            })
            .await
            .is_err()
    );
    assert!(!session.recipe.phases[0].complete);
    assert_eq!(session.recipe.phases[0].published.len(), 3);
    let mut stale = reload(&session);
    let lease_before = std::fs::read(&session.writer.path).unwrap();
    let output_lock = lock_output_root(&session.recipe.phases[0].local)
        .await
        .unwrap();
    session.seal_publication(0).unwrap();
    drop(output_lock);
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), lease_before);

    // Recovery must accept the verified seal even after a later build owns
    // the shared output. Successful historical delivery is not a rewrite grant.
    let destination = session.recipe.phases[0].local.join(relative(0));
    std::fs::write(&destination, b"later build's output").unwrap();
    let stage = session.stage(0);
    std::fs::rename(&stage, stage.with_extension("retained")).unwrap();
    // The old borrowed session must replay before inspecting missing staging.
    stale.publish("docs").await.unwrap();
    assert!(stale.recipe.phases[0].complete);
    let mut recovered = reload(&session);
    assert!(recovered.recipe.phases[0].complete);
    recovered.publish("docs").await.unwrap();
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        b"later build's output"
    );
    recovered.returned(0).unwrap();
    assert_acknowledged(&recovered);
    assert_eq!(recovered.recipe.phases[0].published.len(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn undeclared_result_path_refuses_before_migration_or_any_output_write() {
    let _guard = test_guard!();
    let (_directory, mut session) = docs(2);
    std::fs::write(
        session.stage(0).join("source-sentinel"),
        b"not a declared result",
    )
    .unwrap();
    let before = std::fs::read(&session.writer.path).unwrap();
    let error = session.publish("docs").await.unwrap_err();
    assert!(error.to_string().contains("outside its declared directory"));
    assert_eq!(std::fs::read(&session.writer.path).unwrap(), before);
    assert!(session.recipe.phases[0].publication_journal.is_none());
    assert!(!session.recipe.phases[0].local.join(relative(0)).exists());
    assert_eq!(
        std::fs::read(session.recipe.phases[0].local.join("source-sentinel")).unwrap(),
        b"not an artifact"
    );
    assert_acknowledged(&session);
}
