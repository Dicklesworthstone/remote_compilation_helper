use super::*;
use serde_json::json;

fn manifest() -> SourceManifest {
    SourceManifest::new(
        [("a", 23), ("empty", 0), ("z", 41)]
            .into_iter()
            .map(|(path, len)| SourceFile {
                path: path.into(),
                len,
                sha256: Sha256::digest(vec![0; len as usize]).into(),
                executable: false,
            })
            .collect(),
    )
    .unwrap()
}

fn offer(index: u16, offset: u64) -> SourcePrefixOffer {
    SourcePrefixOffer {
        index,
        offset,
        sha256: encode_hex(&Sha256::digest(vec![0; offset as usize])),
    }
}

#[test]
fn prefix_plan_round_trips_only_declared_partial_members_and_preserves_empty_wire_shape() {
    let manifest = manifest();
    let plain = SourcePlan::all(&manifest).unwrap();
    let encoded = serde_json::to_value(&plain).unwrap();
    assert!(encoded.get("prefixes").is_none());
    assert_eq!(
        serde_json::from_value::<SourcePlan>(encoded).unwrap(),
        plain
    );
    let resumed = SourcePlan::with_prefixes(&manifest, vec![0, 2], vec![offer(0, 13)]).unwrap();
    assert_eq!(resumed.prefix_for(0), Some(&offer(0, 13)));
    assert!(resumed.prefix_for(1).is_none());
    assert!(resumed.prefix_for(2).is_none());
    assert!(resumed.prefix_for(usize::MAX).is_none());
    let round_trip: SourcePlan =
        serde_json::from_slice(&serde_json::to_vec(&resumed).unwrap()).unwrap();
    round_trip.validate(&manifest).unwrap();
    assert_eq!(round_trip, resumed);
}

#[test]
fn prefix_plan_rejects_duplicates_unsorted_nonmissing_empty_and_complete_files() {
    let manifest = manifest();
    for prefixes in [
        vec![offer(0, 1), offer(0, 2)],
        vec![offer(2, 1), offer(0, 1)],
        vec![offer(0, 0)],
        vec![offer(0, 23)],
        vec![offer(0, 24)],
        vec![offer(1, 1)],
        vec![offer(3, 1)],
        vec![offer(u16::MAX, 1)],
    ] {
        assert!(SourcePlan::with_prefixes(&manifest, vec![0, 2], prefixes).is_err());
    }
    assert!(SourcePlan::with_prefixes(&manifest, vec![2], vec![offer(0, 1)]).is_err());
    assert!(SourcePlan::with_prefixes(&manifest, vec![], vec![offer(0, 1)]).is_err());
    let mut wrong_manifest =
        SourcePlan::with_prefixes(&manifest, vec![0], vec![offer(0, 1)]).unwrap();
    wrong_manifest.manifest_sha256 = "00".repeat(32);
    assert!(wrong_manifest.validate(&manifest).is_err());
}

#[test]
fn prefix_plan_rejects_noncanonical_digests_and_unbounded_wire_types() {
    let manifest = manifest();
    for sha256 in [
        String::new(),
        "0".repeat(63),
        "0".repeat(65),
        "AB".repeat(32),
        "zz".repeat(32),
        "0".repeat(MAX_SOURCE_PREFIX_HINT_BYTES),
    ] {
        let mut prefix = offer(0, 1);
        prefix.sha256 = sha256;
        assert!(SourcePlan::with_prefixes(&manifest, vec![0], vec![prefix]).is_err());
    }
    for malformed in [
        json!({"index": 0, "offset": 1, "sha256": "00".repeat(32), "path": "/host"}),
        json!({"index": -1, "offset": 1, "sha256": "00".repeat(32)}),
        json!({"index": 65536, "offset": 1, "sha256": "00".repeat(32)}),
        json!({"index": 0, "offset": -1, "sha256": "00".repeat(32)}),
        json!({"index": 0, "offset": "1", "sha256": "00".repeat(32)}),
        json!({"index": 0, "offset": 1, "sha256": [0, 1]}),
    ] {
        assert!(serde_json::from_value::<SourcePrefixOffer>(malformed).is_err());
    }
    assert!(
        serde_json::from_str::<SourcePrefixOffer>(
            r#"{"index":0,"index":1,"offset":1,"sha256":"00"}"#
        )
        .is_err()
    );
}

#[test]
fn prefix_metadata_bound_accepts_the_last_fitting_array_and_refuses_the_next_offer() {
    let manifest = SourceManifest::new(
        (0..MAX_SOURCE_FILES)
            .map(|index| SourceFile {
                path: format!("file-{index:04}"),
                len: 2,
                sha256: Sha256::digest([0, 0]).into(),
                executable: false,
            })
            .collect(),
    )
    .unwrap();
    let missing: Vec<_> = (0..MAX_SOURCE_FILES)
        .map(|index| u16::try_from(index).unwrap())
        .collect();
    let mut prefixes = Vec::new();
    let mut encoded_bytes = 2;
    for index in &missing {
        let next = offer(*index, 1);
        let added = serde_json::to_vec(&next).unwrap().len() + usize::from(!prefixes.is_empty());
        if encoded_bytes + added > MAX_SOURCE_PREFIX_HINT_BYTES {
            let plan =
                SourcePlan::with_prefixes(&manifest, missing.clone(), prefixes.clone()).unwrap();
            assert_eq!(serde_json::to_vec(&prefixes).unwrap().len(), encoded_bytes);
            assert!(!prefixes.is_empty());
            assert!(serde_json::to_vec(&plan).unwrap().len() < MAX_JSON_RECORD);
            prefixes.push(next);
            assert!(serde_json::to_vec(&prefixes).unwrap().len() > MAX_SOURCE_PREFIX_HINT_BYTES);
            assert!(SourcePlan::with_prefixes(&manifest, missing, prefixes).is_err());
            return;
        }
        prefixes.push(next);
        encoded_bytes += added;
    }
    panic!("maximum manifest must exercise the independent prefix metadata bound");
}
