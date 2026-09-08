//! The enabled platforms, parsed once and checked once.
//!
//! One record per platform, and it is the only place a platform is named. The
//! public ceremony configuration is a projection of it, and the OAuth
//! registrations the callback relies on are the other — "one platform
//! configuration generates both", as the bridge contract puts it. Two lists
//! would be two things to keep in step, and nothing would say when they
//! stopped being in step.
//!
//! What is deliberately NOT here is a circuit. Proving assets belong to the
//! CCDP Distribution, which pins its own; a bridge advertises only the
//! platform/version pairs that distribution serves, and cannot check that
//! itself.
//!
//! That is also why the GitHub client id is not a setting of its own any more.
//! It is the `clientId` of the `github` record, and the secret beside it is the
//! only GitHub value this service holds outside that record — because a secret
//! is the one thing the public configuration must never carry.

use bytes::Bytes;
use serde::Deserialize;
use serde_json::{
    json,
    Map,
    Value,
};

use crate::error::{
    Error,
    Result,
};

/// The platforms a ceremony can run against.
///
/// Closed as a type rather than checked against a list: serde refuses a name
/// outside it while parsing, and names the whole catalog when it does. A
/// `String` here would be a value every reader downstream has to take on
/// faith, and one comparison spelled `== "github"` away from a platform that
/// silently matches nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformId {
    /// Google, whose profile returns its routing state in the fragment.
    Google,
    /// X.
    X,
    /// GitHub, the one platform whose token exchange is confidential and so
    /// the one this service performs itself.
    Github,
}

impl PlatformId {
    /// The wire spelling, which is the key the public configuration uses and
    /// the name an application selects by.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::X => "x",
            Self::Github => "github",
        }
    }
}

/// GitHub's token service implements ceremony version 1 and nothing else, so
/// the configuration must not advertise another: a browser that selected one
/// would send an exchange this service cannot answer.
const GITHUB_ONLY_VERSION: u16 = 1;

/// One enabled platform.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlatformProfile {
    /// Which platform. The catalog is closed, so a name outside it is
    /// refused while this record is parsed.
    pub id: PlatformId,
    /// The public OAuth client identifier. Public — the browser sends it in
    /// the authorization request and the token request reveals it.
    pub client_id: String,
    /// Platform ceremony versions, nonempty and duplicate-free. List order
    /// has no meaning.
    pub versions: Vec<u16>,
}

impl PlatformProfile {
    /// Whether this deployment enables the confidential GitHub exchange.
    pub fn is_github(&self) -> bool {
        self.id == PlatformId::Github
    }
}

/// Parse and check the whole enabled set.
///
/// Everything here fails the process rather than a ceremony. A platform named
/// twice, one carrying no client id, or one advertising a version this service
/// cannot serve is a deployment that starts cleanly and then refuses real
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

    for p in &profiles {
        let id = p.id.as_str();
        if profiles.iter().filter(|q| q.id == p.id).count() > 1 {
            return Err(refuse(format!("{id} appears more than once")));
        }
        if p.client_id.is_empty() {
            return Err(refuse(format!("{id} carries no clientId")));
        }
        if p.versions.is_empty() {
            return Err(refuse(format!("{id} advertises no version")));
        }
        for v in &p.versions {
            if p.versions.iter().filter(|w| *w == v).count() > 1 {
                return Err(refuse(format!(
                    "{id} advertises version {v} more than once"
                )));
            }
            if p.is_github() && *v != GITHUB_ONLY_VERSION {
                return Err(refuse(format!(
                    "github advertises version {v}, and this bridge's token \
                     exchange implements {GITHUB_ONLY_VERSION} only"
                )));
            }
        }
    }
    Ok(profiles)
}

/// The public ceremony configuration, projected from the enabled set.
///
/// This is the projection the module doc names. The client id and the versions
/// travel; nothing about artifacts does, because an application selects a
/// platform and a version and never an artifact. The CCDP origin travels too:
/// it is where the application sends the popup, and the one origin whose
/// Callback artifact this bridge serves.
fn record(redirect_uri: &str, ccdp_origin: &str, platforms: &[PlatformProfile]) -> Value {
    let mut by_id = Map::new();
    for p in platforms {
        by_id.insert(
            p.id.as_str().to_owned(),
            json!({
                "clientId": p.client_id,
                "ceremonyVersions": p.versions,
            }),
        );
    }
    json!({
        "redirectUri": redirect_uri,
        "ccdpOrigin": ccdp_origin,
        "platforms": Value::Object(by_id),
    })
}

/// That record as the bytes it is served in, serialized once at startup.
///
/// Total, and not a `Result`. Serializing a `serde_json::Value` into a `Vec`
/// fails only on a map key that is not a string or a writer that errors, and
/// this has neither: the keys are `String` and the writer is memory. A
/// `Result` here would be an error branch no input can reach.
pub fn config_record(
    redirect_uri: &str,
    ccdp_origin: &str,
    platforms: &[PlatformProfile],
) -> Bytes {
    Bytes::from(
        serde_json::to_vec(&record(redirect_uri, ccdp_origin, platforms))
            .expect("a Value of string keys serializes into memory"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"[{"id":"github","clientId":"Iv1.0","versions":[1]}]"#;

    #[test]
    fn a_well_formed_set_parses() {
        let p = platforms(ONE).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].is_github());
        assert_eq!(p[0].versions, [1]);
    }

    /// Every one of these starts cleanly if unchecked, and then refuses a real
    /// ceremony for a reason nothing in the configuration would have said.
    #[test]
    fn a_set_this_service_cannot_serve_stops_the_process() {
        for (why, json) in [
            ("empty", "[]"),
            (
                "unknown platform",
                r#"[{"id":"twitter","clientId":"a","versions":[1]}]"#,
            ),
            (
                "duplicate platform",
                r#"[{"id":"x","clientId":"a","versions":[1]},{"id":"x","clientId":"b","versions":[1]}]"#,
            ),
            (
                "no versions",
                r#"[{"id":"x","clientId":"a","versions":[]}]"#,
            ),
            (
                "duplicate version",
                r#"[{"id":"x","clientId":"a","versions":[1,1]}]"#,
            ),
            (
                "github on a version its token service does not implement",
                r#"[{"id":"github","clientId":"a","versions":[2]}]"#,
            ),
            (
                "additional member",
                r#"[{"id":"x","clientId":"a","label":"X","versions":[1]}]"#,
            ),
        ] {
            assert!(platforms(json).is_err(), "{why} must be refused");
        }
    }
}
