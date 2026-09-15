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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformId {
    /// Google.
    Google,
    /// X.
    X,
    /// GitHub.
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

/// One enabled platform, with the fields its ceremony takes. In the
/// configuration file, one `[[platforms]]` table keyed by `id`.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "id", rename_all = "lowercase", deny_unknown_fields)]
pub enum PlatformProfile {
    /// Google: the public client id and the ceremony versions advertised.
    Google {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
    },
    /// X: the public client id and the ceremony versions advertised.
    X {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
    },
    /// GitHub: the public client id, the ceremony versions advertised, and
    /// the public credential the browser's token request sends as
    /// `client_secret`.
    Github {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
        /// The OAuth App's client secret, published as
        /// `clientCredential`: public application configuration,
        /// nonempty printable ASCII without whitespace.
        client_credential: String,
    },
}

impl PlatformProfile {
    /// Which platform.
    pub fn id(&self) -> PlatformId {
        match self {
            Self::Google { .. } => PlatformId::Google,
            Self::X { .. } => PlatformId::X,
            Self::Github { .. } => PlatformId::Github,
        }
    }

    /// The public OAuth client identifier.
    pub fn client_id(&self) -> &str {
        match self {
            Self::Google { client_id, .. }
            | Self::X { client_id, .. }
            | Self::Github { client_id, .. } => client_id,
        }
    }

    /// The ceremony versions advertised. List order has no meaning.
    pub fn versions(&self) -> &[u16] {
        match self {
            Self::Google { versions, .. }
            | Self::X { versions, .. }
            | Self::Github { versions, .. } => versions,
        }
    }

    /// The public client credential the entry carries: GitHub's.
    pub fn client_credential(&self) -> Option<&str> {
        match self {
            Self::Github {
                client_credential, ..
            } => Some(client_credential),
            Self::Google { .. } | Self::X { .. } => None,
        }
    }
}

/// Check the enabled set: nonempty, each platform once, each with a client id,
/// a nonempty, duplicate-free version list and, where its ceremony takes one,
/// a client credential of nonempty printable ASCII without whitespace.
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
        let id = p.id().as_str();
        if profiles
            .iter()
            .filter(|q| q.id() == p.id())
            .nth(1)
            .is_some()
        {
            return Err(refuse(format!("{id} appears more than once")));
        }
        if p.client_id().is_empty() {
            return Err(refuse(format!("{id} carries no client_id")));
        }
        if p.versions().is_empty() {
            return Err(refuse(format!("{id} advertises no version")));
        }
        for v in p.versions() {
            if p.versions().iter().filter(|w| *w == v).nth(1).is_some() {
                return Err(refuse(format!(
                    "{id} advertises version {v} more than once"
                )));
            }
        }
        if let Some(credential) = p.client_credential() {
            if credential.is_empty() {
                return Err(refuse(format!("{id} carries an empty client_credential")));
            }
            if !credential.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
                return Err(refuse(format!(
                    "{id}'s client_credential is not printable ASCII \
                     without whitespace"
                )));
            }
        }
    }
    Ok(profiles)
}

/// The public ceremony configuration: what one deployment publishes.
pub struct CeremonyConfig<'a> {
    /// The CCDP Distribution this deployment selects.
    pub ccdp_origin: &'a crate::origin::Origin,
    /// The enabled platforms, checked.
    pub platforms: &'a [PlatformProfile],
}

impl CeremonyConfig<'_> {
    fn record(&self) -> Value {
        let mut by_id = Map::new();
        for p in self.platforms {
            let mut entry = json!({
                "clientId": p.client_id(),
                "ceremonyVersions": p.versions(),
            });
            if let Some(credential) = p.client_credential() {
                entry["clientCredential"] = Value::from(credential);
            }
            by_id.insert(p.id().as_str().to_owned(), entry);
        }
        json!({
            "ccdpOrigin": self.ccdp_origin,
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

    const ONE: &str = r#"[{"id":"github","client_id":"Iv1.0","versions":[1],"client_credential":"c0ffee"}]"#;

    /// Parse records as the configuration file would, then check them.
    fn checked(json: &str) -> Result<Vec<PlatformProfile>> {
        let records: Vec<PlatformProfile> =
            serde_json::from_str(json).map_err(|e| Error::Config {
                detail: e.to_string(),
            })?;
        platforms(records)
    }

    /// One github entry whose `client_credential` is `credential`.
    fn github_with(credential: impl Into<Value>) -> String {
        json!([{
            "id": "github",
            "client_id": "a",
            "versions": [1],
            "client_credential": credential.into(),
        }])
        .to_string()
    }

    #[test]
    fn a_well_formed_set_parses() {
        let p = checked(ONE).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].id(), PlatformId::Github);
        assert_eq!(p[0].client_id(), "Iv1.0");
        assert_eq!(p[0].versions(), [1]);
        assert_eq!(p[0].client_credential(), Some("c0ffee"));
    }

    /// The record carries a github entry's credential as
    /// `clientCredential`, and an entry that has none carries no such
    /// key.
    #[test]
    fn the_record_publishes_the_credential_where_there_is_one() {
        let platforms = checked(
            r#"[{"id":"github","client_id":"Iv1.0","versions":[1],"client_credential":"c0ffee"},{"id":"x","client_id":"xc","versions":[2]}]"#,
        )
        .unwrap();
        let ccdp_origin =
            crate::origin::Origin::parse("CCDP_ORIGIN", "https://lib.id").unwrap();
        let record: Value = serde_json::from_slice(
            &CeremonyConfig {
                ccdp_origin: &ccdp_origin,
                platforms: &platforms,
            }
            .serialized(),
        )
        .unwrap();

        let github = record["platforms"]["github"].as_object().unwrap();
        let mut keys: Vec<&str> = github.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ceremonyVersions", "clientCredential", "clientId"]);
        assert_eq!(github["clientCredential"], "c0ffee");

        let x = record["platforms"]["x"].as_object().unwrap();
        let mut keys: Vec<&str> = x.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ceremonyVersions", "clientId"]);
    }

    /// Each of these is refused at startup.
    #[test]
    fn a_set_this_service_cannot_serve_stops_the_process() {
        let around = |byte: u8| format!("c0f{}fee", char::from(byte));
        for (why, json) in [
            ("empty", "[]".to_owned()),
            (
                "unknown platform",
                r#"[{"id":"twitter","client_id":"a","versions":[1]}]"#.to_owned(),
            ),
            (
                "duplicate platform",
                r#"[{"id":"x","client_id":"a","versions":[1]},{"id":"x","client_id":"b","versions":[1]}]"#.to_owned(),
            ),
            (
                "no versions",
                r#"[{"id":"x","client_id":"a","versions":[]}]"#.to_owned(),
            ),
            (
                "duplicate version",
                r#"[{"id":"x","client_id":"a","versions":[1,1]}]"#.to_owned(),
            ),
            (
                "additional member",
                r#"[{"id":"x","client_id":"a","label":"X","versions":[1]}]"#.to_owned(),
            ),
            (
                "a github entry with no credential",
                r#"[{"id":"github","client_id":"a","versions":[1]}]"#.to_owned(),
            ),
            ("a null credential", github_with(Value::Null)),
            ("a credential that is not a string", github_with(1)),
            ("an empty credential", github_with("")),
            ("a credential carrying a space", github_with(around(b' '))),
            ("a credential carrying a tab", github_with(around(b'\t'))),
            ("a credential carrying a control byte", github_with(around(7))),
            ("a credential carrying DEL", github_with(around(0x7F))),
            ("a credential outside ASCII", github_with(around(0xE9))),
            (
                "a credential on a platform that has none",
                r#"[{"id":"x","client_id":"a","versions":[1],"client_credential":"c0ffee"}]"#.to_owned(),
            ),
        ] {
            assert!(checked(&json).is_err(), "{why} must be refused");
        }
    }

    /// A refusal names the field, never the value.
    #[test]
    fn a_refused_credential_is_named_and_not_quoted() {
        let err =
            checked(&github_with("zzMarkerzz fee")).expect_err("a space is refused");
        let text = err.to_string();
        assert!(text.contains("client_credential"), "{text}");
        assert!(!text.contains("zzMarkerzz"), "{text}");
    }
}
