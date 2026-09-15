//! X's authorization, driven from a blank page to the redirect: a session
//! restored from saved cookies or signed in through X's own pages, then the
//! consent page. Chrome presents itself as a person's desktop Chrome.

use std::time::{
    Duration,
    Instant,
};

use base64::Engine;
use chromiumoxide::{
    browser::BrowserConfigBuilder,
    cdp::browser_protocol::{
        emulation::{
            SetAutomationOverrideParams,
            SetDeviceMetricsOverrideParams,
            SetUserAgentOverrideParams,
            UserAgentBrandVersion,
            UserAgentMetadata,
        },
        input::{
            DispatchKeyEventParams,
            DispatchKeyEventType,
            DispatchMouseEventParams,
            DispatchMouseEventType,
        },
        network::{
            CookieParam,
            CookieSameSite,
            Headers,
            SetExtraHttpHeadersParams,
            TimeSinceEpoch,
        },
        page::AddScriptToEvaluateOnNewDocumentParams,
    },
    Page,
};
use serde::{
    Deserialize,
    Serialize,
};

use super::{
    budget,
    headed,
    Platform,
    Session,
    POLL,
};
use crate::stack::{
    optional,
    required,
};

/// The Chrome this driver presents itself as.
const USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

/// Chrome's flags: what chromiumoxide adds by default less `--enable-automation`
/// and `--disable-extensions`, then the presentation.
const FLAGS: &[&str] = &[
    "--disable-background-networking",
    "--enable-features=NetworkService,NetworkServiceInProcess",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-breakpad",
    "--disable-client-side-phishing-detection",
    "--disable-component-extensions-with-background-pages",
    "--disable-default-apps",
    "--disable-features=TranslateUI,PasswordManager",
    "--disable-hang-monitor",
    "--disable-ipc-flooding-protection",
    "--disable-popup-blocking",
    "--disable-prompt-on-repost",
    "--disable-renderer-backgrounding",
    "--disable-save-password-bubble",
    "--disable-sync",
    "--force-color-profile=srgb",
    "--metrics-recording-only",
    "--no-default-browser-check",
    "--no-first-run",
    "--enable-blink-features=IdleDetection",
    "--disable-blink-features=AutomationControlled",
    "--window-size=1440,900",
    "--lang=en-US",
];

/// What every new document runs before the page's own scripts.
const STEALTH: &str = include_str!("stealth.js");

/// The two hosts a session's cookies are set for.
const HOSTS: [&str; 2] = ["x.com", "twitter.com"];

/// The text a signed-in X page shows.
const SIGNED_IN: [&str; 3] = ["Home", "Explore", "Notifications"];

/// The text X shows for a sign-in it refused.
const REFUSED: [&str; 4] = [
    "Could not log you in",
    "Something went wrong",
    "incorrect",
    "temporarily limited your login",
];

/// The username field, on X's landing page and in its sign-in dialog.
const USERNAME: &str =
    "input[name='username_or_email'], input[autocomplete='username'], input[name='username']";
const PASSWORD: &str = "input[name='password']";
/// The field X asks the e-mail address into on a sign-in it examines.
const CHALLENGE: &str = "input[data-testid='ocfEnterTextTextInput']";

/// One cookie of a saved session. `same_site` is absent where Chrome
/// reported none; `expires` is `0` for a session cookie, or where the list
/// carries none.
#[derive(Serialize, Deserialize)]
struct StoredCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: bool,
    http_only: bool,
    same_site: Option<CookieSameSite>,
    #[serde(default)]
    expires: f64,
}

impl StoredCookie {
    /// The parameter that sets this cookie for `host`, with the domain it
    /// was saved under rewritten to `host`.
    fn param(&self, host: &str) -> CookieParam {
        let mut param = CookieParam::new(self.name.clone(), self.value.clone());
        param.url = Some(format!("https://{host}/"));
        param.domain = Some(self.domain.replace("x.com", host));
        param.path = Some(self.path.clone());
        param.secure = Some(self.secure);
        param.http_only = Some(self.http_only);
        param.same_site = self.same_site.clone();
        if self.expires > 0.0 {
            param.expires = Some(TimeSinceEpoch::new(self.expires));
        }
        param
    }
}

/// The X test account: its credentials, the e-mail address X may ask for,
/// and the session cookies it was last exported with.
pub struct Account {
    username: String,
    password: String,
    email: Option<String>,
    cookies: Vec<StoredCookie>,
}

impl Account {
    /// The account `prefix` names: `{prefix}_USERNAME` and `{prefix}_PASSWORD`
    /// are required; `{prefix}_EMAIL` and `{prefix}_COOKIES` (base64 of what
    /// [`Authorization::fresh_cookies`] prints) are optional.
    pub fn from_env(prefix: &str) -> Account {
        let cookies = match optional(&format!("{prefix}_COOKIES")) {
            Some(encoded) => {
                let json = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .unwrap_or_else(|e| panic!("{prefix}_COOKIES is base64: {e}"));
                serde_json::from_slice(&json).unwrap_or_else(|e| {
                    panic!("{prefix}_COOKIES decodes to a cookie list: {e}")
                })
            }
            None => Vec::new(),
        };
        Account {
            username: required(&format!("{prefix}_USERNAME")),
            password: required(&format!("{prefix}_PASSWORD")),
            email: optional(&format!("{prefix}_EMAIL")),
            cookies,
        }
    }

    /// The account's handle.
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// X's authorization request, as the client builds it, and the account
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
            .append_pair("response_type", "code")
            .append_pair("client_id", self.client_id)
            .append_pair("redirect_uri", self.redirect_uri)
            .append_pair("scope", "tweet.read users.read")
            .append_pair("state", self.state)
            .append_pair("code_challenge", self.code_challenge)
            .append_pair("code_challenge_method", "S256")
            .finish();
        format!("https://x.com/i/oauth2/authorize?{query}")
    }

    /// Sign in through X's own pages, the saved cookies unused, and export
    /// the session: the `_COOKIES` value for the next runs, as base64 of the
    /// cookie list.
    pub async fn fresh_cookies(&self) -> String {
        let mut session = Session::open(self).await;
        self.sign_in(&mut session).await;
        let cookies: Vec<StoredCookie> = session
            .page
            .get_cookies()
            .await
            .expect("the cookies Chrome holds for x.com")
            .into_iter()
            .filter(|c| c.domain.ends_with("x.com"))
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
            .collect();
        let _ = session.close().await;
        assert!(
            cookies.iter().any(|c| c.name == "auth_token"),
            "the session carries X's auth_token cookie"
        );
        base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&cookies).expect("a cookie list serializes"))
    }

    /// Whether the page shows a signed-in X.
    async fn signed_in(session: &Session) -> bool {
        let text = session.body_text().await;
        SIGNED_IN.iter().all(|mark| text.contains(mark))
    }

    /// Wait up to `within` for a signed-in X page.
    async fn signed_in_within(session: &Session, within: Duration) -> bool {
        let started = Instant::now();
        while started.elapsed() < within {
            if Self::signed_in(session).await {
                return true;
            }
            tokio::time::sleep(POLL).await;
        }
        false
    }

    /// The saved session, set in Chrome and honoured by `x.com/home`.
    async fn restored(&self, session: &Session) -> bool {
        if self.account.cookies.is_empty() {
            return false;
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            session.page.goto("https://x.com/"),
        )
        .await;
        let params: Vec<CookieParam> = HOSTS
            .iter()
            .flat_map(|host| self.account.cookies.iter().map(|c| c.param(host)))
            .collect();
        session
            .page
            .set_cookies(params)
            .await
            .expect("Chrome takes the saved session's cookies");
        session.navigate("https://x.com/home").await;
        let restored = Self::signed_in_within(session, Duration::from_secs(20)).await;
        session.trace("restored").await;
        if !restored {
            eprintln!(
                "the saved session was not honoured; signing in. Page: {}",
                session
                    .body_text()
                    .await
                    .chars()
                    .take(200)
                    .collect::<String>()
            );
        }
        restored
    }

    /// Sign in through X's own pages: a web search for X, its result in the
    /// tab X opens, the page's own sign-in link, the username, the password,
    /// the e-mail address if X asks, and Cloudflare's check if it runs.
    async fn sign_in(&self, session: &mut Session) {
        let mut jitter = Jitter::seeded();
        let known = session.tabs().await;
        let _ = tokio::time::timeout(
            Duration::from_secs(15),
            session
                .page
                .goto("https://www.bing.com/search?q=twitter+login"),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        if session.evaluate(BING_CONSENT).await == "accepted" {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let clicked = session.evaluate(BING_RESULT).await;
        assert_ne!(clicked, "not_found", "the search lists x.com");

        if let Some(opened) = session.tab_opened(&known, Duration::from_secs(8)).await {
            session.adopt(opened, self).await;
        }
        let loading = Instant::now();
        while loading.elapsed() < Duration::from_secs(15)
            && session.evaluate("document.readyState").await != "complete"
        {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        session.evaluate(X_CONSENT).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        session.trace("x-landing").await;
        if session.location().await.contains("/home") {
            return;
        }

        if !present(session, USERNAME, Duration::from_secs(2)).await {
            session.evaluate(SIGN_IN_LINK).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            session.trace("after-sign-in-link").await;
            if session.location().await.contains("/home") {
                return;
            }
        }

        if present(session, USERNAME, Duration::from_secs(10)).await {
            for _ in 0..3 {
                let (x, y) =
                    (200.0 + jitter.unit() * 600.0, 150.0 + jitter.unit() * 400.0);
                move_mouse(&session.page, x, y, &mut jitter).await;
                tokio::time::sleep(Duration::from_millis(jitter.between(200, 600))).await;
            }
            session
                .evaluate("window.scrollBy(0, 50 + Math.random() * 100)")
                .await;
            tokio::time::sleep(Duration::from_millis(jitter.between(300, 700))).await;
            session.evaluate("window.scrollBy(0, -50)").await;
            tokio::time::sleep(Duration::from_millis(jitter.between(200, 500))).await;
            move_to(session, USERNAME, &mut jitter).await;
            tokio::time::sleep(Duration::from_millis(jitter.between(200, 500))).await;
            type_like_a_person(session, USERNAME, &self.account.username, &mut jitter)
                .await;
            tokio::time::sleep(Duration::from_millis(jitter.between(500, 1000))).await;
            session.trace("username-typed").await;
            if session.evaluate(NEXT_BUTTON).await == "not_found" {
                press(&session.page, "Tab").await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                press(&session.page, "Enter").await;
            }
            tokio::time::sleep(Duration::from_secs(8)).await;
        }
        session.trace("after-username").await;
        self.refusal_check(session).await;

        if present(session, CHALLENGE, Duration::from_secs(3)).await {
            match self.account.email.as_deref() {
                Some(email) => {
                    type_like_a_person(session, CHALLENGE, email, &mut jitter).await;
                    tokio::time::sleep(Duration::from_millis(jitter.between(300, 600)))
                        .await;
                    press(&session.page, "Enter").await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    session.trace("after-challenge").await;
                }
                None => assert!(
                    headed(),
                    "X asked for the account's e-mail address: set X_TEST_ALICE_EMAIL"
                ),
            }
        }
        if Self::signed_in(session).await {
            return;
        }

        // In a visible Chrome a person may be completing a step X added.
        let patience = if headed() {
            budget()
        } else {
            Duration::from_secs(10)
        };
        assert!(
            present(session, PASSWORD, patience).await,
            "X shows the password field. On: {}\nPage: {}",
            session.location().await,
            session
                .body_text()
                .await
                .chars()
                .take(400)
                .collect::<String>()
        );
        move_to(session, PASSWORD, &mut jitter).await;
        tokio::time::sleep(Duration::from_millis(jitter.between(200, 400))).await;
        type_like_a_person(session, PASSWORD, &self.account.password, &mut jitter).await;
        tokio::time::sleep(Duration::from_millis(jitter.between(400, 800))).await;
        session.trace("password-typed").await;
        click_by_text(session, &["Log in", "Continue"]).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        session.trace("after-log-in").await;
        self.refusal_check(session).await;

        let checking = Instant::now();
        while session.location().await.contains("/account/access")
            && checking.elapsed() < Duration::from_secs(30)
        {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let patience = if headed() {
            budget()
        } else {
            Duration::from_secs(20)
        };
        let signed_in = Self::signed_in_within(session, patience).await;
        session.trace("signed-in").await;
        assert!(
            signed_in,
            "X shows the signed-in page after the password. On: {}\nPage: {}",
            session.location().await,
            session
                .body_text()
                .await
                .chars()
                .take(400)
                .collect::<String>()
        );
    }

    /// A refusal on the page stops the run, with the page's text; in a
    /// visible Chrome it is printed, and the person at the keyboard goes on.
    async fn refusal_check(&self, session: &Session) {
        let text = session.body_text().await;
        if !REFUSED.iter().any(|mark| text.contains(mark)) {
            return;
        }
        let refusal = format!(
            "X refused the sign-in. On: {}\nPage: {}",
            session.location().await,
            text.chars().take(400).collect::<String>()
        );
        assert!(headed(), "{refusal}");
        eprintln!("{refusal}");
    }
}

impl Platform for Authorization<'_> {
    fn configure(&self, config: BrowserConfigBuilder) -> BrowserConfigBuilder {
        let mut config = config
            .disable_default_args()
            .viewport(None)
            .arg(format!("--user-agent={USER_AGENT}"));
        for flag in FLAGS {
            config = config.arg(*flag);
        }
        config
    }

    /// The automation override off, the viewport at the window's size, the
    /// user agent and its client hints, and the stealth script on every
    /// new document.
    async fn prepare(&self, page: &Page) {
        let _ = page
            .execute(SetAutomationOverrideParams { enabled: false })
            .await;
        let _ = page
            .execute(SetDeviceMetricsOverrideParams::new(1440, 900, 1., false))
            .await;
        let brand = |brand: &str, version: &str| UserAgentBrandVersion {
            brand: brand.to_owned(),
            version: version.to_owned(),
        };
        let _ = page
            .execute(SetUserAgentOverrideParams {
                user_agent: USER_AGENT.to_owned(),
                accept_language: Some("en-US,en;q=0.9".to_owned()),
                platform: Some("macOS".to_owned()),
                user_agent_metadata: Some(UserAgentMetadata {
                    brands: Some(vec![
                        brand("Chromium", "145"),
                        brand("Not:A-Brand", "99"),
                        brand("Google Chrome", "145"),
                    ]),
                    full_version_list: Some(vec![
                        brand("Chromium", "145.0.0.0"),
                        brand("Not:A-Brand", "99.0.0.0"),
                        brand("Google Chrome", "145.0.0.0"),
                    ]),
                    platform: "macOS".to_owned(),
                    platform_version: "15.3.0".to_owned(),
                    architecture: "arm".to_owned(),
                    model: String::new(),
                    mobile: false,
                    bitness: Some("64".to_owned()),
                    wow64: Some(false),
                }),
            })
            .await;
        let _ = page
            .execute(SetExtraHttpHeadersParams::new(Headers::new(serde_json::json!({
                "sec-ch-ua": "\"Chromium\";v=\"145\", \"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"macOS\"",
            }))))
            .await;
        let _ = page
            .execute(AddScriptToEvaluateOnNewDocumentParams::new(STEALTH))
            .await;
    }

    fn state(&self) -> &str {
        self.state
    }

    /// A signed-in X, then the authorization URL from the page's own
    /// scripts, the consent button, and whatever X puts in the way until
    /// the redirect is requested: a sign-in page once, Cloudflare's check.
    async fn authorize(&self, session: &mut Session) -> String {
        let started = Instant::now();
        if !self.restored(session).await {
            self.sign_in(session).await;
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
        session.evaluate("window.scrollBy(0, 200)").await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut redirect = session.watch_redirect(self.redirect_uri).await;
        session.navigate(&self.url()).await;
        let mut consented: Option<Instant> = None;
        let mut signed_in_again = false;
        let mut last_path = String::new();

        while started.elapsed() < budget() {
            if let Some(url) = redirect.seen() {
                return url;
            }
            let url = session.location().await;
            if url.starts_with(self.redirect_uri) {
                return url;
            }
            let path = url::Url::parse(&url)
                .map(|u| u.path().to_owned())
                .unwrap_or_default();
            if path != last_path {
                session.trace("authorize").await;
                last_path = path.clone();
            }

            if path.starts_with("/i/oauth2/authorize") {
                session.evaluate(X_CONSENT).await;
                if consented.is_none_or(|at| at.elapsed() > Duration::from_secs(10))
                    && session.evaluate(CONSENT_CLICK).await == "clicked"
                {
                    consented = Some(Instant::now());
                }
            } else if path.starts_with("/i/flow/login") || path == "/login" {
                assert!(
                    !signed_in_again,
                    "X asked to sign in twice. Page: {}",
                    session
                        .body_text()
                        .await
                        .chars()
                        .take(400)
                        .collect::<String>()
                );
                self.sign_in(session).await;
                signed_in_again = true;
                consented = None;
                redirect = session.watch_redirect(self.redirect_uri).await;
                session.navigate(&self.url()).await;
            } else if !path.starts_with("/account/access") {
                let text = session.body_text().await;
                assert!(
                    !text.contains("Something went wrong"),
                    "X answered an error on {url}. Page: {}",
                    text.chars().take(400).collect::<String>()
                );
            }
            tokio::time::sleep(POLL).await;
        }

        panic!(
            "no authorization in {:?}.\nstopped on: {}\npage said: {}",
            budget(),
            session.location().await,
            session
                .body_text()
                .await
                .chars()
                .take(400)
                .collect::<String>()
        );
    }
}

/// Bing's cookie banner accepted, if it is shown.
const BING_CONSENT: &str = r#"(() => {
    const button = document.querySelector('#bnp_btn_accept')
        || [...document.querySelectorAll('button')].find(b => /accept|agree/i.test(b.textContent));
    if (button) { button.click(); return 'accepted'; }
    return 'no_banner';
})()"#;

/// The first result on x.com or twitter.com clicked, else the first result.
const BING_RESULT: &str = r#"(() => {
    const cites = [...document.querySelectorAll('#b_results .b_algo cite, #b_results .b_algo .b_attribution')];
    for (const cite of cites) {
        if (/twitter\.com|x\.com/i.test(cite.textContent)) {
            const a = cite.closest('.b_algo')?.querySelector('h2 a, h3 a');
            if (a) { a.click(); return 'cite'; }
        }
    }
    const first = document.querySelector('#b_results .b_algo h2 a, #b_results .b_algo h3 a');
    if (first) { first.click(); return 'first:' + first.textContent.trim(); }
    return 'not_found';
})()"#;

/// X's cookie banner accepted, if it is shown.
const X_CONSENT: &str = r#"(() => {
    const span = [...document.querySelectorAll('span')].find(s => s.textContent.includes('Accept all cookies'));
    const button = span && span.closest('button,[role=button],div[role=button]');
    if (button) { button.click(); return 'accepted'; }
    return 'no_banner';
})()"#;

/// The page's own sign-in link clicked.
const SIGN_IN_LINK: &str = r#"(() => {
    const links = [...document.querySelectorAll('a[href="/login"], a[href="/i/flow/login"]')];
    if (links.length) { links[0].click(); return 'link'; }
    const buttons = [...document.querySelectorAll('button, [role="button"], a')];
    const button = buttons.find(b => /^(sign in|log in)$/i.test(b.textContent.trim()));
    if (button) { button.click(); return 'button:' + button.textContent.trim(); }
    return 'not_found';
})()"#;

/// The button that submits the username step clicked: "Next" in the
/// sign-in dialog, "Continue" on the landing page.
const NEXT_BUTTON: &str = r#"(() => {
    const buttons = [...document.querySelectorAll('button, [role="button"]')];
    const next = buttons.find(b => /^(next|continue)$/i.test(b.textContent.trim()));
    if (next) { next.click(); return 'clicked'; }
    return 'not_found';
})()"#;

/// The consent button clicked from the page's own scripts.
const CONSENT_CLICK: &str = r#"(() => {
    const button = document.querySelector("[data-testid='OAuth_Consent_Button']");
    if (button) { button.click(); return 'clicked'; }
    return 'absent';
})()"#;

/// Whether `selector` appears on the page within `within`.
async fn present(session: &Session, selector: &str, within: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < within {
        if session.page.find_element(selector).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// A trusted click on the first button whose text is one of `texts`: the
/// element is marked from the page, found by the mark, and clicked through
/// CDP input.
async fn click_by_text(session: &Session, texts: &[&str]) {
    let wanted = serde_json::to_string(texts).expect("a list of strings");
    session
        .evaluate(&format!(
            "[...document.querySelectorAll('button,[role=button]')].find(b => {wanted}.includes(b.innerText.trim()))?.setAttribute('data-libid-click', '1')"
        ))
        .await;
    session.click("[data-libid-click='1']").await;
    session
        .evaluate("document.querySelector(\"[data-libid-click='1']\")?.removeAttribute('data-libid-click')")
        .await;
}

/// The mouse moved to `(x, y)` in a few steps.
async fn move_mouse(page: &Page, to_x: f64, to_y: f64, jitter: &mut Jitter) {
    let (mut x, mut y) = (to_x * 0.3, to_y * 0.3);
    for i in 1..=5 {
        let t = f64::from(i) / 5.0;
        x += (to_x - x) * t + (jitter.unit() - 0.5) * 8.0;
        y += (to_y - y) * t + (jitter.unit() - 0.5) * 8.0;
        let _ = page
            .execute(
                DispatchMouseEventParams::builder()
                    .r#type(DispatchMouseEventType::MouseMoved)
                    .x(x)
                    .y(y)
                    .build()
                    .expect("a mouse move"),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(jitter.between(25, 60))).await;
    }
}

/// The mouse moved onto the element `selector` names.
async fn move_to(session: &Session, selector: &str, jitter: &mut Jitter) {
    let quoted = serde_json::Value::String(selector.to_owned()).to_string();
    let center = session
        .evaluate(&format!(
            "(() => {{ const el = document.querySelector({quoted}); if (!el) return '720,450'; \
             const r = el.getBoundingClientRect(); \
             return Math.round(r.x + r.width / 2) + ',' + Math.round(r.y + r.height / 2); }})()"
        ))
        .await;
    let mut parts = center.split(',').filter_map(|s| s.parse::<f64>().ok());
    if let (Some(x), Some(y)) = (parts.next(), parts.next()) {
        move_mouse(&session.page, x, y, jitter).await;
    }
}

/// `text` typed into the element `selector` names, one key at a time with
/// 60 to 180 milliseconds between keys.
async fn type_like_a_person(
    session: &Session,
    selector: &str,
    text: &str,
    jitter: &mut Jitter,
) {
    if let Ok(element) = session.page.find_element(selector).await {
        let _ = element.click().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    for ch in text.chars() {
        let key = ch.to_string();
        let events = [
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::RawKeyDown)
                .key(key.clone())
                .build(),
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::Char)
                .text(key.clone())
                .build(),
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyUp)
                .key(key.clone())
                .build(),
        ];
        for event in events {
            let _ = session.page.execute(event.expect("a key event")).await;
        }
        tokio::time::sleep(Duration::from_millis(jitter.between(60, 180))).await;
    }
}

/// One named key pressed and released.
async fn press(page: &Page, key: &str) {
    let (code, text, key_code) = match key {
        "Enter" => ("Enter", Some("\r"), 13),
        "Tab" => ("Tab", None, 9),
        other => (other, None, 0),
    };
    let mut down = DispatchKeyEventParams::builder()
        .r#type(if text.is_some() {
            DispatchKeyEventType::KeyDown
        } else {
            DispatchKeyEventType::RawKeyDown
        })
        .key(key)
        .code(code)
        .windows_virtual_key_code(key_code)
        .native_virtual_key_code(key_code);
    if let Some(text) = text {
        down = down.text(text);
    }
    let _ = page.execute(down.build().expect("a key event")).await;
    let _ = page
        .execute(
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyUp)
                .key(key)
                .code(code)
                .windows_virtual_key_code(key_code)
                .native_virtual_key_code(key_code)
                .build()
                .expect("a key event"),
        )
        .await;
}

/// A source of small variations: an xorshift generator seeded from the
/// clock and the process id.
struct Jitter(u64);

impl Jitter {
    fn seeded() -> Jitter {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_nanos() as u64;
        Jitter((nanos ^ u64::from(std::process::id()).rotate_left(32)) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A value in `[low, high)`.
    fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low)
    }

    /// A value in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}
