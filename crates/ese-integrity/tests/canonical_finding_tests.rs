#![allow(clippy::unwrap_used, clippy::expect_used)]

//! ese-integrity structural anomalies normalize onto `forensicnomicon::report`.

use ese_integrity::EseStructuralAnomaly;
use forensicnomicon::report::{Observation, Source};

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = EseStructuralAnomaly::DirtyDatabase { db_state: 2 };
    let f = a.to_finding(Source {
        analyzer: "srum-forensic".to_string(),
        scope: "ESE".to_string(),
        version: None,
    });
    assert_eq!(f.code, "SRUM-ESE-DIRTY-DATABASE");
    assert!(f.severity.is_some());
}
