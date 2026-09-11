//! One authorization code, obtained from Chrome signed in as the test
//! account. The browser never talks to the bridge: GitHub redirects to
//! `{redirect_uri}?code=…`, and the code is read off the request Chrome makes
//! to that address, where nothing listens.

use std::time::Duration;

use base64::Engine;
use chromiumoxide::{
    cdp::browser_protocol::network::{
        CookieParam,
        CookieSameSite,
        EnableParams,
        EventRequestWillBeSent,
        SetCookiesParams,
        TimeSinceEpoch,
    },
    Browser,
    BrowserConfig,
    Page,
};
use futures_util::StreamExt;
use serde::{
    Deserialize,
    Serialize,
};

use super::stack::required;

/// How long the whole authorization may take, a login included: five
/// minutes headless, fifteen in a visible Chrome, where a person may be
/// completing a step.
fn budget() -> Duration {
    Duration::from_secs(if headed() { 900 } else { 300 })
}

/// How long the page is left alone between two looks at it.
const POLL: Duration = Duration::from_millis(500);

/// The origin every cookie is set for.
const GITHUB: &str = "https://github.com/";

/// A cookie as the account's session is stored: the fields Chrome needs to
/// set it again.
#[derive(Serialize, Deserialize)]
struct StoredCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: Option<CookieSameSite>,
    expires: f64,
}

impl StoredCookie {
    /// The parameter that sets this cookie for [`GITHUB`]. A `__Host-` cookie
    /// carries no domain.
    fn param(&self) -> CookieParam {
        let mut param = CookieParam::new(self.name.clone(), self.value.clone());
        param.url = Some(GITHUB.to_owned());
        param.path = Some(self.path.clone());
        param.secure = Some(self.secure);
        param.http_only = Some(self.http_only);
        param.same_site = self.same_site.clone();
        if !self.name.starts_with("__Host-") {
            param.domain = Some(self.domain.clone());
        }
        if self.expires > 0.0 {
            param.expires = Some(TimeSinceEpoch::new(self.expires));
        }
        param
    }
}

/// The GitHub test account: its credentials, its TOTP secret when it has
/// one, and the session cookies it was last exported with.
pub struct Account {
    username: String,
    password: String,
    totp_secret: Option<String>,
    cookies: Vec<StoredCookie>,
}

impl Account {
    /// The account `prefix` names: `{prefix}_USERNAME` and `{prefix}_PASSWORD`
    /// are required; `{prefix}_TOTP_SECRET` (the base32 key of its
    /// authenticator app) and `{prefix}_COOKIES` (base64 of what
    /// [`Account::fresh_cookies`] prints) are optional.
    pub fn from_env(prefix: &str) -> Account {
        let cookies = match std::env::var(format!("{prefix}_COOKIES")) {
            Ok(encoded) if !encoded.is_empty() => {
                let json = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .unwrap_or_else(|e| panic!("{prefix}_COOKIES is base64: {e}"));
                serde_json::from_slice(&json).unwrap_or_else(|e| {
                    panic!("{prefix}_COOKIES decodes to a cookie list: {e}")
                })
            }
            _ => Vec::new(),
        };
        Account {
            username: required(&format!("{prefix}_USERNAME")),
            password: required(&format!("{prefix}_PASSWORD")),
            totp_secret: std::env::var(format!("{prefix}_TOTP_SECRET"))
                .ok()
                .filter(|s| !s.is_empty()),
            cookies,
        }
    }

    /// Sign in and export the session: the `{prefix}_COOKIES` value for the
    /// next runs, as base64 of the cookie list.
    pub async fn fresh_cookies(&self) -> String {
        let session = Session::open(self).await;
        session
            .page
            .goto("https://github.com/login")
            .await
            .expect("github.com");
        session.drive(None).await;
        let cookies = session
            .page
            .get_cookies()
            .await
            .expect("the cookies Chrome holds for github.com")
            .into_iter()
            .filter(|c| c.domain.ends_with("github.com"))
            .map(|c| StoredCookie {
                name: c.name,
                value: c.value,
                domain: c.domain,
                path: c.path,
                secure: c.secure,
                http_only: c.http_only,
                same_site: c.same_site,
                expires: c.expires,
            })
            .collect::<Vec<_>>();
        session.close().await;
        base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&cookies).expect("a cookie list serializes"))
    }

    /// The current TOTP code for this account.
    fn totp(&self) -> String {
        let secret: String = self
            .totp_secret
            .as_deref()
            .expect("GitHub asked for a TOTP code: set the account's _TOTP_SECRET")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_uppercase();
        let bytes = totp_rs::Secret::Encoded(secret)
            .to_bytes()
            .expect("a base32 TOTP secret");
        totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, bytes)
            .expect("a TOTP over that secret")
            .generate_current()
            .expect("a clock at or after the epoch")
    }
}

/// GitHub's authorization request, as the client builds it.
pub struct AuthorizeRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
}

impl AuthorizeRequest<'_> {
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

/// What GitHub redirected with.
pub struct Grant {
    pub code: String,
}

impl Grant {
    /// The code GitHub issues for `request` once `account` has authorized it.
    pub async fn obtained(account: &Account, request: &AuthorizeRequest<'_>) -> Grant {
        let session = Session::open(account).await;

        // Subscribed before navigating, so the redirect cannot be missed.
        let mut requests = session
            .page
            .event_listener::<EventRequestWillBeSent>()
            .await
            .expect("the requests this page is about to make");
        let (found, redirected) = tokio::sync::oneshot::channel::<String>();
        let wanted = request.redirect_uri.to_owned();
        let watching = tokio::spawn(async move {
            let mut found = Some(found);
            while let Some(sent) = requests.next().await {
                if sent.request.url.starts_with(&wanted) {
                    if let Some(tx) = found.take() {
                        let _ = tx.send(sent.request.url.clone());
                    }
                    return;
                }
            }
        });

        let _ = session.page.goto(request.url()).await;
        let landed = session
            .drive(Some((request.redirect_uri, redirected)))
            .await;
        watching.abort();
        session.close().await;

        let code = query_value(&landed, "code")
            .unwrap_or_else(|| panic!("the redirect carries a code: {landed}"));
        assert_eq!(
            query_value(&landed, "state").as_deref(),
            Some(request.state),
            "the redirect carries the state that was sent"
        );
        Grant { code }
    }
}

/// A Chrome page with the account's cookies set.
struct Session<'a> {
    account: &'a Account,
    browser: Browser,
    driving: tokio::task::JoinHandle<()>,
    page: Page,
}

impl<'a> Session<'a> {
    async fn open(account: &'a Account) -> Session<'a> {
        let mut config = BrowserConfig::builder()
            .arg("--no-sandbox")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage");
        if headed() {
            config = config.with_head();
        }
        let (browser, mut handler) = Browser::launch(
            config
                .build()
                .unwrap_or_else(|e| panic!("a browser configuration: {e}")),
        )
        .await
        .expect("Chrome; install one, or name it in CHROME");
        let driving =
            tokio::spawn(async move { while handler.next().await.is_some() {} });

        let page = browser
            .new_page("about:blank")
            .await
            .expect("a page to authorize in");
        page.execute(EnableParams::default())
            .await
            .expect("network events on this page");
        if !account.cookies.is_empty() {
            let params = account.cookies.iter().map(StoredCookie::param).collect();
            page.execute(SetCookiesParams::new(params))
                .await
                .expect("the account's cookies set");
        }
        Session {
            account,
            browser,
            driving,
            page,
        }
    }

    /// Whatever GitHub puts in the way, until `redirect` fires or, with no
    /// redirect to wait for, until the page is signed in. Returns the URL
    /// reached.
    async fn drive(
        &self,
        redirect: Option<(&str, tokio::sync::oneshot::Receiver<String>)>,
    ) -> String {
        let (redirect_uri, mut redirected) = match redirect {
            Some((uri, rx)) => (Some(uri), Some(rx)),
            None => (None, None),
        };
        let started = std::time::Instant::now();
        let mut filled = false;
        let mut totp_step_submitted: Option<u64> = None;
        let mut rate_limited = 0u64;

        while started.elapsed() < budget() {
            if let Some(rx) = redirected.as_mut() {
                if let Ok(url) = rx.try_recv() {
                    return url;
                }
            }
            let url = self.page.url().await.ok().flatten().unwrap_or_default();
            let path = url::Url::parse(&url)
                .map(|u| u.path().to_owned())
                .unwrap_or_default();

            if let Some(uri) = redirect_uri {
                // Chrome keeps the URL it could not load.
                if url.starts_with(uri) {
                    return url;
                }
            } else if url == "https://github.com/" {
                return url;
            }

            if path == "/login" || path == "/session" {
                if self
                    .body_text()
                    .await
                    .to_lowercase()
                    .contains("too many requests")
                    || self.body_text().await.to_lowercase().contains("rate limit")
                {
                    rate_limited += 1;
                    assert!(
                        rate_limited <= 3,
                        "GitHub rate-limited the login three times"
                    );
                    tokio::time::sleep(Duration::from_secs(30 * rate_limited)).await;
                    let _ = self.page.reload().await;
                    filled = false;
                    continue;
                }
                if !filled && self.page.find_element("#login_field").await.is_ok() {
                    self.fill("#login_field", &self.account.username).await;
                    self.fill("#password", &self.account.password).await;
                    self.click("input[type=submit][name=commit]").await;
                    filled = true;
                }
            } else if path == "/sessions/two-factor/app" {
                let step = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("a clock at or after the epoch")
                    .as_secs()
                    / 30;
                if totp_step_submitted != Some(step)
                    && self.page.find_element("#app_totp").await.is_ok()
                {
                    self.fill("#app_totp", &self.account.totp()).await;
                    self.click("button[type=submit]").await;
                    totp_step_submitted = Some(step);
                }
            } else if path.starts_with("/sessions/two-factor") {
                let _ = self
                    .page
                    .goto("https://github.com/sessions/two-factor/app")
                    .await;
            } else if path == "/login/oauth/authorize" {
                if self
                    .page
                    .find_element("button[name='authorize'][value='1']")
                    .await
                    .is_ok()
                {
                    self.click("button[name='authorize'][value='1']").await;
                } else {
                    let text = self.body_text().await;
                    assert!(
                        !text.contains("redirect_uri") && !text.contains("Be careful"),
                        "GitHub refused the authorization request; the App's registered \
                         callback URL and LIBID_TEST_REDIRECT_URI differ. Page: {}",
                        text.chars().take(400).collect::<String>()
                    );
                }
            } else if path.starts_with("/sessions/verified-device") && !headed() {
                panic!(
                    "GitHub asked for device verification. Confirm it once in a visible \
                     Chrome (BROWSER_HEAD=1) and export the session, or give the account a \
                     TOTP method. Page: {}",
                    self.body_text().await.chars().take(400).collect::<String>()
                );
            }
            tokio::time::sleep(POLL).await;
        }

        let url = self.page.url().await.ok().flatten().unwrap_or_default();
        panic!(
            "no authorization in {:?}.\nstopped on: {url}\npage said: {}",
            budget(),
            self.body_text().await.chars().take(400).collect::<String>()
        );
    }

    /// The page's visible text, whitespace collapsed.
    async fn body_text(&self) -> String {
        let text = match self.page.find_element("body").await {
            Ok(body) => body.inner_text().await.ok().flatten().unwrap_or_default(),
            Err(_) => String::new(),
        };
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Type into a field, if it is on the page.
    async fn fill(&self, selector: &str, value: &str) {
        if let Ok(element) = self.page.find_element(selector).await {
            let _ = element.click().await;
            let _ = element.type_str(value).await;
        }
    }

    /// Click, if it is there.
    async fn click(&self, selector: &str) {
        if let Ok(element) = self.page.find_element(selector).await {
            let _ = element.click().await;
        }
    }

    async fn close(mut self) {
        let _ = self.browser.close().await;
        self.driving.abort();
    }
}

/// Whether Chrome is visible: `BROWSER_HEAD` is set. A visible Chrome is
/// left on a page a person completes, device verification included.
fn headed() -> bool {
    std::env::var("BROWSER_HEAD").is_ok()
}

/// One query parameter of `url`, percent-decoded.
fn query_value(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}
