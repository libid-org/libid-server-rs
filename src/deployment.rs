//! The enabled platforms, parsed once and checked once.
//!
//! One record per platform, and it is the only place a platform is named. The
//! public ceremony configuration and the prover profiles embedded in the shell
//! are two projections of it — "projections of one enabled set, not
//! independently maintained platform lists", as the deployment contract puts
//! it. Two lists would be two things to keep in step, and nothing would say
//! when they stopped being in step.
//!
//! That is also why the GitHub client id is not a setting of its own any more.
//! It is the `clientId` of the `github` record, and the secret beside it is the
//! only GitHub value this service holds outside that record — because a secret
//! is the one thing the public configuration must never carry.

use serde::Deserialize;

use crate::error::{
    Error,
    Result,
};

/// The platforms a ceremony can run against. Closed: a name outside it is a
/// deployment naming something this service has no profile for, which is a
/// startup error rather than an entry nobody will ever select.
const CATALOG: [&str; 3] = ["google", "x", "github"];

/// GitHub's token service implements ceremony version 1 and nothing else, so
/// the configuration must not advertise another: a browser that selected one
/// would send an exchange this service cannot answer.
const GITHUB_ONLY_VERSION: u16 = 1;

/// One ceremony version of one platform, and the circuit that proves it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlatformVersion {
    /// The platform ceremony version, as the digest binds it.
    pub version: u16,
    /// The immutable circuit for this exact platform and version. One entry
    /// per advertised pair: the prover selects by both, not by platform.
    pub circuit_url: String,
}

/// One enabled platform.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlatformProfile {
    /// One of `google`, `x`, `github`. The catalog is closed: a name outside
    /// it is a deployment naming something this service has no profile for.
    pub id: String,
    /// The public OAuth client identifier. Public — the browser sends it in
    /// the authorization request and the token request reveals it.
    pub client_id: String,
    /// Nonempty and duplicate-free.
    pub versions: Vec<PlatformVersion>,
}

impl PlatformProfile {
    /// Whether this deployment enables the confidential GitHub exchange.
    pub fn is_github(&self) -> bool {
        self.id == "github"
    }
}

/// Parse and check the whole enabled set.
///
/// Everything here fails the process rather than a ceremony. A platform
/// advertised with a circuit that does not exist, or a version this service
/// cannot serve, is a deployment that starts cleanly and then refuses real
/// users — which is the failure this function exists to move earlier.
pub fn platforms(json: &str) -> Result<Vec<PlatformProfile>> {
    let refuse = |detail: String| Error::Config {
        detail: format!("CEREMONY_PLATFORMS: {detail}"),
    };

    let profiles: Vec<PlatformProfile> =
        serde_json::from_str(json).map_err(|e| refuse(e.to_string()))?;
    if profiles.is_empty() {
        return Err(refuse("names no platform, so no ceremony can run".into()));
    }

    for (i, p) in profiles.iter().enumerate() {
        if !CATALOG.contains(&p.id.as_str()) {
            return Err(refuse(format!(
                "[{i}] names {:?}, which is not one of {CATALOG:?}",
                p.id
            )));
        }
        if profiles.iter().filter(|q| q.id == p.id).count() > 1 {
            return Err(refuse(format!("{} appears more than once", p.id)));
        }
        if p.client_id.is_empty() {
            return Err(refuse(format!("{} carries no clientId", p.id)));
        }
        if p.versions.is_empty() {
            return Err(refuse(format!("{} advertises no version", p.id)));
        }
        for (j, v) in p.versions.iter().enumerate() {
            if p.versions.iter().filter(|w| w.version == v.version).count() > 1 {
                return Err(refuse(format!(
                    "{} advertises version {} more than once",
                    p.id, v.version
                )));
            }
            if p.is_github() && v.version != GITHUB_ONLY_VERSION {
                return Err(refuse(format!(
                    "github advertises version {}, and this service's token \
                     exchange implements {GITHUB_ONLY_VERSION} only",
                    v.version
                )));
            }
            crate::immutable_url(
                &format!("CEREMONY_PLATFORMS[{i}].versions[{j}]"),
                &v.circuit_url,
            )?;
        }
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"[{"id":"github","clientId":"Iv1.0","versions":[{"version":1,"circuitUrl":"https://a.example/v1/bearer_link.json"}]}]"#;

    #[test]
    fn a_well_formed_set_parses() {
        let p = platforms(ONE).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].is_github());
        assert_eq!(p[0].versions[0].version, 1);
    }

    /// Every one of these starts cleanly if unchecked, and then refuses a real
    /// ceremony for a reason nothing in the configuration would have said.
    #[test]
    fn a_set_this_service_cannot_serve_stops_the_process() {
        for (why, json) in [
            ("empty", "[]"),
            (
                "unknown platform",
                r#"[{"id":"twitter","clientId":"a","versions":[{"version":1,"circuitUrl":"https://a.example/c.json"}]}]"#,
            ),
            (
                "duplicate platform",
                r#"[{"id":"x","clientId":"a","versions":[{"version":1,"circuitUrl":"https://a.example/c.json"}]},{"id":"x","clientId":"b","versions":[{"version":1,"circuitUrl":"https://a.example/c.json"}]}]"#,
            ),
            (
                "no versions",
                r#"[{"id":"x","clientId":"a","versions":[]}]"#,
            ),
            (
                "duplicate version",
                r#"[{"id":"x","clientId":"a","versions":[{"version":1,"circuitUrl":"https://a.example/c.json"},{"version":1,"circuitUrl":"https://a.example/d.json"}]}]"#,
            ),
            (
                "github on a version its token service does not implement",
                r#"[{"id":"github","clientId":"a","versions":[{"version":2,"circuitUrl":"https://a.example/c.json"}]}]"#,
            ),
            (
                "circuit url with a query",
                r#"[{"id":"x","clientId":"a","versions":[{"version":1,"circuitUrl":"https://a.example/c.json?v=2"}]}]"#,
            ),
            (
                "additional member",
                r#"[{"id":"x","clientId":"a","label":"X","versions":[{"version":1,"circuitUrl":"https://a.example/c.json"}]}]"#,
            ),
        ] {
            assert!(platforms(json).is_err(), "{why} must be refused");
        }
    }
}
