//! One authorization code, obtained from Chrome signed in as a test account.
//! The browser never talks to the bridge: the platform redirects to
//! `{redirect_uri}?code=…`, and the code is read off the request Chrome makes
//! to that address, where nothing listens. What a platform's pages look like
//! is the platform module's; the browser, the redirect watch and the code are
//! shared.

pub mod github;
pub mod x;

use std::{
    collections::HashSet,
    sync::atomic::{
        AtomicU32,
        Ordering,
    },
    time::{
        Duration,
        Instant,
    },
};

use chromiumoxide::{
    browser::BrowserConfigBuilder,
    cdp::browser_protocol::{
        network::{
            EnableParams,
            EventRequestWillBeSent,
        },
        target::TargetId,
    },
    page::ScreenshotParams,
    Browser,
    BrowserConfig,
    Page,
};
use futures_util::StreamExt;

/// How long the whole authorization may take, a login included: five
/// minutes headless, fifteen in a visible Chrome, where a person may be
/// completing a step.
pub fn budget() -> Duration {
    Duration::from_secs(if headed() { 900 } else { 300 })
}

/// How long the page is left alone between two looks at it.
pub const POLL: Duration = Duration::from_millis(500);

/// One platform's authorization: how its Chrome is configured, and how its
/// pages are driven from a blank tab to the redirect.
pub trait Platform {
    /// Chrome's launch configuration, on top of the suite's own flags.
    fn configure(&self, config: BrowserConfigBuilder) -> BrowserConfigBuilder {
        config
    }

    /// What a page needs before it navigates anywhere.
    async fn prepare(&self, _page: &Page) {}

    /// The `state` the authorization request carries.
    fn state(&self) -> &str;

    /// From a blank page to the redirect. Returns the URL reached: the
    /// redirect, carrying the code.
    async fn authorize(&self, session: &mut Session) -> String;
}

/// What the platform redirected with.
pub struct Grant {
    pub code: String,
    /// Chrome closing, on its own task.
    closing: tokio::task::JoinHandle<()>,
}

impl Grant {
    /// The code the platform issues once its authorization has been driven
    /// to the redirect. Chrome is closing when this returns; [`Grant::closed`]
    /// waits for it.
    pub async fn obtained(platform: &impl Platform) -> Grant {
        let mut session = Session::open(platform).await;
        let landed = platform.authorize(&mut session).await;
        let closing = session.close();

        let code = query_value(&landed, "code")
            .unwrap_or_else(|| panic!("the redirect carries a code: {landed}"));
        assert_eq!(
            query_value(&landed, "state").as_deref(),
            Some(platform.state()),
            "the redirect carries the state that was sent"
        );
        Grant { code, closing }
    }

    /// Chrome has closed.
    pub async fn closed(self) {
        let _ = self.closing.await;
    }
}

/// The redirect request Chrome makes, watched for from before the navigation
/// that leads to it.
pub struct Redirect {
    found: tokio::sync::oneshot::Receiver<String>,
    watching: tokio::task::JoinHandle<()>,
}

impl Redirect {
    /// The redirect URL, once Chrome has requested it.
    pub fn seen(&mut self) -> Option<String> {
        self.found.try_recv().ok()
    }
}

impl Drop for Redirect {
    fn drop(&mut self) {
        self.watching.abort();
    }
}

/// A Chrome page with network events on, signed in as nobody.
pub struct Session {
    browser: Browser,
    driving: tokio::task::JoinHandle<()>,
    pub page: Page,
    /// How many traces this session has written.
    traced: AtomicU32,
}

/// The page's form controls and buttons, as JSON: what a driver selects on.
const CONTROLS: &str = r#"JSON.stringify({
    inputs: [...document.querySelectorAll('input, textarea')].map(i => ({
        name: i.name, type: i.type, autocomplete: i.autocomplete,
        testid: i.dataset.testid, placeholder: i.placeholder, visible: !!i.offsetParent,
    })),
    buttons: [...document.querySelectorAll('button, [role=button], a[href]')].map(b => ({
        text: (b.innerText || '').trim().slice(0, 60), testid: b.dataset.testid,
        href: b.getAttribute('href'), visible: !!b.offsetParent,
    })).filter(b => b.text || b.testid),
}, null, 1)"#;

impl Session {
    /// A Chrome as `platform` wants it, with one blank page prepared.
    pub async fn open(platform: &impl Platform) -> Session {
        let mut config = BrowserConfig::builder()
            .arg("--no-sandbox")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage");
        if headed() {
            config = config.with_head();
        }
        let config = platform.configure(config);
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
        let mut session = Session {
            browser,
            driving,
            page,
            traced: AtomicU32::new(0),
        };
        session.prepare(platform).await;
        session
    }

    /// A tab the site opened becomes the driven page, prepared like the
    /// first one.
    pub async fn adopt(&mut self, page: Page, platform: &impl Platform) {
        self.page = page;
        self.prepare(platform).await;
    }

    /// The tabs Chrome has open now, by target.
    pub async fn tabs(&self) -> HashSet<TargetId> {
        self.browser
            .pages()
            .await
            .unwrap_or_default()
            .iter()
            .map(|page| page.target_id().clone())
            .collect()
    }

    /// A tab that is not among `known`, if one opens within `within`.
    pub async fn tab_opened(
        &self,
        known: &HashSet<TargetId>,
        within: Duration,
    ) -> Option<Page> {
        let started = Instant::now();
        while started.elapsed() < within {
            if let Ok(pages) = self.browser.pages().await {
                if let Some(page) = pages
                    .into_iter()
                    .find(|page| !known.contains(page.target_id()))
                {
                    return Some(page);
                }
            }
            tokio::time::sleep(POLL).await;
        }
        None
    }

    /// Network events on, and whatever `platform` needs on a page.
    async fn prepare(&mut self, platform: &impl Platform) {
        self.page
            .execute(EnableParams::default())
            .await
            .expect("network events on this page");
        platform.prepare(&self.page).await;
    }

    /// Watch this page for a request to `redirect_uri`. Subscribed before
    /// the navigation, so the redirect cannot be missed.
    pub async fn watch_redirect(&self, redirect_uri: &str) -> Redirect {
        let mut requests = self
            .page
            .event_listener::<EventRequestWillBeSent>()
            .await
            .expect("the requests this page is about to make");
        let (tx, found) = tokio::sync::oneshot::channel::<String>();
        let wanted = redirect_uri.to_owned();
        let watching = tokio::spawn(async move {
            let mut tx = Some(tx);
            while let Some(sent) = requests.next().await {
                if sent.request.url.starts_with(&wanted) {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(sent.request.url.clone());
                    }
                    return;
                }
            }
        });
        Redirect { found, watching }
    }

    /// What `js` evaluates to on the page, as text: a string as itself,
    /// anything else as JSON, nothing on failure.
    pub async fn evaluate(&self, js: &str) -> String {
        let Ok(result) = self.page.evaluate(js).await else {
            return String::new();
        };
        match result.value() {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        }
    }

    /// The page's URL as its own scripts see it.
    pub async fn location(&self) -> String {
        self.evaluate("window.location.href").await
    }

    /// Navigate from the page's own scripts, and return at once.
    pub async fn navigate(&self, url: &str) {
        let quoted = serde_json::Value::String(url.to_owned()).to_string();
        self.evaluate(&format!("window.location.href = {quoted}"))
            .await;
    }

    /// A screenshot and a text dump of the page (its URL, controls and
    /// text) into the directory `BROWSER_TRACE` names, numbered in order,
    /// when it is set.
    pub async fn trace(&self, label: &str) {
        let Ok(dir) = std::env::var("BROWSER_TRACE") else {
            return;
        };
        let n = self.traced.fetch_add(1, Ordering::Relaxed);
        let stem = std::path::Path::new(&dir).join(format!("{n:02}-{label}"));
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(png) = self
            .page
            .screenshot(ScreenshotParams::builder().build())
            .await
        {
            let _ = std::fs::write(stem.with_extension("png"), png);
        }
        let dump = format!(
            "{}\n\n{}\n\n{}\n",
            self.location().await,
            self.evaluate(CONTROLS).await,
            self.body_text().await
        );
        let _ = std::fs::write(stem.with_extension("txt"), dump);
    }

    /// The page's visible text, whitespace collapsed.
    pub async fn body_text(&self) -> String {
        let text = match self.page.find_element("body").await {
            Ok(body) => body.inner_text().await.ok().flatten().unwrap_or_default(),
            Err(_) => String::new(),
        };
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Type into a field, if it is on the page.
    pub async fn fill(&self, selector: &str, value: &str) {
        if let Ok(element) = self.page.find_element(selector).await {
            let _ = element.click().await;
            let _ = element.type_str(value).await;
        }
    }

    /// Click, if it is there.
    pub async fn click(&self, selector: &str) {
        if let Ok(element) = self.page.find_element(selector).await {
            let _ = element.click().await;
        }
    }

    /// Close Chrome, on its own task: the caller decides whether to wait.
    pub fn close(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let _ = self.browser.close().await;
            self.driving.abort();
        })
    }
}

/// Whether Chrome is visible: `BROWSER_HEAD` is set. A visible Chrome is
/// left on a page a person completes, device verification included.
pub fn headed() -> bool {
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
