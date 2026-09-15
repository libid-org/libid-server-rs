//! GitHub's authorization, driven from a blank page to the redirect: the
//! login form, the TOTP step, the authorize button.

use std::time::Duration;

use super::{
    budget,
    headed,
    Platform,
    Session,
    POLL,
};
use crate::stack::required;

/// The six-digit TOTP code for `secret` at `time`, as an authenticator app
/// shows it: SHA-1, 30-second steps. `secret` is the base32 key as GitHub
/// displays it; spaces and case are ignored, and GitHub's 80-bit keys are
/// shorter than the RFC's minimum, which `new_unchecked` does not enforce.
fn totp_code(secret: &str, time: u64) -> String {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    let bytes = totp_rs::Secret::Encoded(normalized)
        .to_bytes()
        .expect("a base32 TOTP secret");
    totp_rs::TOTP::new_unchecked(totp_rs::Algorithm::SHA1, 6, 1, 30, bytes).generate(time)
}

/// The GitHub test account: its credentials, and its TOTP secret when it
/// has one.
pub struct Account {
    username: String,
    password: String,
    totp_secret: Option<String>,
}

impl Account {
    /// The account `prefix` names: `{prefix}_USERNAME` and `{prefix}_PASSWORD`
    /// are required; `{prefix}_TOTP_SECRET` (the base32 key of its
    /// authenticator app) is optional.
    pub fn from_env(prefix: &str) -> Account {
        Account {
            username: required(&format!("{prefix}_USERNAME")),
            password: required(&format!("{prefix}_PASSWORD")),
            totp_secret: std::env::var(format!("{prefix}_TOTP_SECRET"))
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }

    /// The account's login, as GitHub spells it.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The current TOTP code for this account.
    fn totp(&self) -> String {
        let secret = self
            .totp_secret
            .as_deref()
            .expect("GitHub asked for a TOTP code: set the account's _TOTP_SECRET");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_secs();
        totp_code(secret, now)
    }
}

/// GitHub's authorization request, as the client builds it, and the account
/// that grants it.
pub struct Authorization<'a> {
    pub account: &'a Account,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
}

impl Authorization<'_> {
    /// The URL to open.
    pub fn url(&self) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", self.client_id)
            .append_pair("redirect_uri", self.redirect_uri)
            .append_pair("scope", "read:user")
            .append_pair("state", self.state)
            .append_pair("code_challenge", self.code_challenge)
            .append_pair("code_challenge_method", "S256")
            .finish();
        format!("https://github.com/login/oauth/authorize?{query}")
    }
}

impl Platform for Authorization<'_> {
    fn state(&self) -> &str {
        self.state
    }

    /// Whatever GitHub puts in the way, until the redirect is requested or
    /// Chrome lands on it; GitHub's own error page starts the authorization
    /// over, three times at most.
    async fn authorize(&self, session: &mut Session) -> String {
        let start = self.url();
        let mut redirect = session.watch_redirect(self.redirect_uri).await;
        let _ = session.page.goto(start.clone()).await;

        let started = std::time::Instant::now();
        let mut filled = false;
        let mut totp_step_submitted: Option<u64> = None;
        let mut rate_limited = 0u64;
        let mut github_errored = 0u64;

        while started.elapsed() < budget() {
            if let Some(url) = redirect.seen() {
                return url;
            }
            let url = session.page.url().await.ok().flatten().unwrap_or_default();
            let path = url::Url::parse(&url)
                .map(|u| u.path().to_owned())
                .unwrap_or_default();

            // Chrome keeps the URL it could not load.
            if url.starts_with(self.redirect_uri) {
                return url;
            }

            let text = session.body_text().await.to_lowercase();
            // GitHub's own error page, on whatever path: the authorization
            // starts over.
            if text.contains("couldn't respond to your request in time")
                || text.contains("something went wrong")
            {
                github_errored += 1;
                assert!(
                    github_errored <= 3,
                    "GitHub answered its error page three times. Page: {}",
                    text.chars().take(200).collect::<String>()
                );
                tokio::time::sleep(Duration::from_secs(10 * github_errored)).await;
                let _ = session.page.goto(start.clone()).await;
                filled = false;
                totp_step_submitted = None;
                continue;
            }

            if path == "/login" || path == "/session" {
                if text.contains("too many requests") || text.contains("rate limit") {
                    rate_limited += 1;
                    assert!(
                        rate_limited <= 3,
                        "GitHub rate-limited the login three times"
                    );
                    tokio::time::sleep(Duration::from_secs(30 * rate_limited)).await;
                    let _ = session.page.reload().await;
                    filled = false;
                    continue;
                }
                if !filled && session.page.find_element("#login_field").await.is_ok() {
                    session.fill("#login_field", &self.account.username).await;
                    session.fill("#password", &self.account.password).await;
                    session.click("input[type=submit][name=commit]").await;
                    filled = true;
                }
            } else if path == "/sessions/two-factor/app" {
                let step = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("a clock at or after the epoch")
                    .as_secs()
                    / 30;
                if totp_step_submitted != Some(step)
                    && session.page.find_element("#app_totp").await.is_ok()
                {
                    session.fill("#app_totp", &self.account.totp()).await;
                    session.click("button[type=submit]").await;
                    totp_step_submitted = Some(step);
                }
            } else if path.starts_with("/sessions/two-factor") {
                let _ = session
                    .page
                    .goto("https://github.com/sessions/two-factor/app")
                    .await;
            } else if path == "/login/oauth/authorize" {
                if session
                    .page
                    .find_element("button[name='authorize'][value='1']")
                    .await
                    .is_ok()
                {
                    session.click("button[name='authorize'][value='1']").await;
                } else {
                    let text = session.body_text().await;
                    assert!(
                        !text.contains("redirect_uri") && !text.contains("Be careful"),
                        "GitHub refused the authorization request; the App's registered \
                         callback URL and LIBID_TEST_PUBLIC_ORIGIN differ. Page: {}",
                        text.chars().take(400).collect::<String>()
                    );
                }
            } else if path.starts_with("/sessions/verified-device") && !headed() {
                panic!(
                    "GitHub asked for device verification: the account has no TOTP \
                     method. Give it one, or confirm the device once in a visible Chrome \
                     (BROWSER_HEAD=1). Page: {}",
                    session
                        .body_text()
                        .await
                        .chars()
                        .take(400)
                        .collect::<String>()
                );
            }
            tokio::time::sleep(POLL).await;
        }

        let url = session.page.url().await.ok().flatten().unwrap_or_default();
        panic!(
            "no authorization in {:?}.\nstopped on: {url}\npage said: {}",
            budget(),
            session
                .body_text()
                .await
                .chars()
                .take(400)
                .collect::<String>()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::totp_code;

    /// An 80-bit key as GitHub displays it, spaces and lowercase included,
    /// gives the code an authenticator app gives.
    #[test]
    fn a_github_setup_key_gives_the_authenticators_code() {
        assert_eq!(totp_code("jbsw y3dp ehpk 3pxp", 1_700_000_000), "324550");
        assert_eq!(totp_code("JBSWY3DPEHPK3PXP", 1_700_000_000), "324550");
    }
}
