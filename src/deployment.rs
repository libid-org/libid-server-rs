//! The enabled platforms, checked once at startup, and the public ceremony
//! configuration projected from them.

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

/// The platforms a ceremony can run against. A name outside this catalog is
/// refused while parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformId {
    /// Google.
    Google,
    /// X.
    X,
    /// GitHub, whose token exchange this service performs.
    Github,
}

impl PlatformId {
    /// The wire spelling: the key in the public configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::X => "x",
            Self::Github => "github",
        }
    }
}

/// The one GitHub ceremony version this service's token exchange implements.
const GITHUB_ONLY_VERSION: u16 = 1;

/// One enabled platform.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlatformProfile {
    /// Which platform.
    pub id: PlatformId,
    /// The public OAuth client identifier. Also accepted as `client_id`.
    #[serde(alias = "client_id")]
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

/// Check the enabled set: nonempty, each platform once, each with a client id
/// and a nonempty, duplicate-free version list that this service can serve.
pub fn platforms(profiles: Vec<PlatformProfile>) -> Result<Vec<PlatformProfile>> {
    let refuse = |detail: String| Error::Config {
        detail: format!("platforms: {detail}"),
    };

    if profiles.is_empty() {
        return Err(refuse(
            "no platform is enabled; add a [[platforms]] table to the configuration file"
                .into(),
        ));
    }

    for p in &profiles {
        let id = p.id.as_str();
        if profiles.iter().filter(|q| q.id == p.id).nth(1).is_some() {
            return Err(refuse(format!("{id} appears more than once")));
        }
        if p.client_id.is_empty() {
            return Err(refuse(format!("{id} carries no clientId")));
        }
        if p.versions.is_empty() {
            return Err(refuse(format!("{id} advertises no version")));
        }
        for v in &p.versions {
            if p.versions.iter().filter(|w| *w == v).nth(1).is_some() {
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

/// The public ceremony configuration: what one deployment publishes.
pub struct CeremonyConfig<'a> {
    /// The path providers redirect back to, under the bridge's origin.
    pub callback_path: &'a str,
    /// The CCDP Distribution this deployment selects.
    pub ccdp_origin: &'a str,
    /// The enabled platforms, checked.
    pub platforms: &'a [PlatformProfile],
}

impl CeremonyConfig<'_> {
    fn record(&self) -> Value {
        let (callback_path, ccdp_origin, platforms) =
            (self.callback_path, self.ccdp_origin, self.platforms);
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
            "callbackPath": callback_path,
            "ccdpOrigin": ccdp_origin,
            "platforms": Value::Object(by_id),
        })
    }

    /// That record as the bytes it is served in, serialized once at startup.
    pub fn serialized(&self) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&self.record())
                .expect("a Value of string keys serializes into memory"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"[{"id":"github","clientId":"Iv1.0","versions":[1]}]"#;

    /// Parse records as the configuration file would, then check them.
    fn checked(json: &str) -> Result<Vec<PlatformProfile>> {
        let records: Vec<PlatformProfile> =
            serde_json::from_str(json).map_err(|e| Error::Config {
                detail: e.to_string(),
            })?;
        platforms(records)
    }

    #[test]
    fn a_well_formed_set_parses() {
        let p = checked(ONE).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].is_github());
        assert_eq!(p[0].versions, [1]);
    }

    /// Each of these is refused at startup.
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
            assert!(checked(json).is_err(), "{why} must be refused");
        }
    }
}
