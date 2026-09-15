//! The live ceremony suite: real MPC-TLS sessions through a notary of this
//! suite, against real github.com and api.x.com, with the bridge under test
//! publishing the configuration a ceremony starts from. Built only with
//! `--features live-ceremony`; needs `GH_OAUTH_CLIENT_ID`,
//! `GH_OAUTH_CLIENT_SECRET` (the App's client secret, which the bridge
//! publishes as the public `clientCredential`) and
//! `LIBID_TEST_PUBLIC_ORIGIN`, for the GitHub authorization rung the test
//! account (`GH_TEST_ALICE_*`) and a Chrome, and for the X authorization rung
//! `X_OAUTH_CLIENT_ID`, `LIBID_TEST_X_REDIRECT_URI` and the X test account
//! (`X_TEST_ALICE_*`). A missing variable fails the run.

#[path = "../common/bridge.rs"]
// Each suite uses its part of the module.
#[allow(dead_code)]
mod bridge;
mod browser;
mod github;
mod notary;
mod prover;
mod session;
mod stack;
mod x;

use std::time::{
    Duration,
    Instant,
};

use base64::Engine;
use browser::Grant;
use notary::Notary;
use sha2::{
    Digest,
    Sha256,
};
use stack::{
    redirect_uri,
    required,
    Stack,
};

/// A code GitHub refuses: twenty hex characters, the shape of a real one.
const SPENT_CODE: &str = "0123456789abcdef0123";

/// The longest bearer the client commits (REQ-PLAT-30).
const BEARER_CEILING: usize = 4096;

/// How long an X authorization code lives once issued (REQ-PLAT-33).
const X_CODE_LIFETIME: Duration = Duration::from_secs(30);

/// A `state` no earlier run sent: the process id and the clock, in hex.
fn fresh_state() -> String {
    format!(
        "{:x}{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_nanos()
    )
}

/// Unpadded url-safe base64 of SHA-256 over `input`: 43 characters.
fn s256(input: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

/// The bearer a token session yielded: nonempty printable ASCII with no
/// carriage return or line feed, within the ceiling (REQ-PLAT-36).
fn assert_bearer(bearer: &str) {
    assert!(!bearer.is_empty());
    assert!(
        bearer.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
        "the bearer is printable ASCII"
    );
    assert!(bearer.len() <= BEARER_CEILING, "{} bytes", bearer.len());
    eprintln!("bearer: {} bytes", bearer.len());
}

/// A refused authorization code fails the token session with GitHub's own
/// answer, `bad_verification_code`, and the steps reached: a notary was
/// dialled, MPC-TLS completed against github.com and GitHub answered. The
/// client id and the credential are the ones the bridge published.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_code_fails_the_token_session_with_githubs_answer() {
    let stack = Stack::attesting().await;
    let published = stack.published().await;
    let failed = github::exchange(
        &stack.notary,
        github::token_request(&github::TokenFields {
            client_id: &published.client_id,
            code: SPENT_CODE,
            redirect_uri: &redirect_uri(),
            code_verifier: &s256("placeholder"),
            client_secret: &published.credential,
        }),
    )
    .await
    .err()
    .expect("GitHub refuses a code it did not issue");
    let message = failed.to_string();
    assert!(message.contains("bad_verification_code"), "{message}");
    assert!(
        message.contains("TlsHandshakeComplete"),
        "the session reached GitHub before it failed: {message}"
    );
}

/// A credential GitHub refuses fails the token session with GitHub's own
/// answer, `incorrect_client_credentials`. The client id is the published
/// one: a placeholder id is answered `404` by GitHub, a different path.
#[tokio::test(flavor = "multi_thread")]
async fn a_credential_github_refuses_fails_the_token_session() {
    let stack = Stack::attesting().await;
    let published = stack.published().await;
    let failed = github::exchange(
        &stack.notary,
        github::token_request(&github::TokenFields {
            client_id: &published.client_id,
            code: SPENT_CODE,
            redirect_uri: &redirect_uri(),
            code_verifier: &s256("placeholder"),
            client_secret: "not-this-deployments-credential",
        }),
    )
    .await
    .err()
    .expect("GitHub refuses a credential it did not issue");
    let message = failed.to_string();
    assert!(
        message.contains("incorrect_client_credentials"),
        "{message}"
    );
    assert!(
        message.contains("TlsHandshakeComplete"),
        "the session reached GitHub before it failed: {message}"
    );
}

/// A bearer GitHub did not issue fails the identity session with GitHub's
/// own answer (a `4xx`, `401 Unauthorized` today) and the steps reached. No
/// account is needed.
#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_github_refuses_fails_the_identity_session() {
    stack::logging();
    let notary = Notary::attesting().await;
    let failed = github::identity(&notary, "not-a-bearer")
        .await
        .err()
        .expect("GitHub refuses a bearer it did not issue");
    let message = failed.to_string();
    assert!(message.contains("API returned 4"), "{message}");
    assert!(
        message.contains("TlsHandshakeComplete"),
        "the session reached GitHub before it failed: {message}"
    );
}

/// The GitHub ceremony end to end: the bridge under test publishes the App's
/// client id and credential, Chrome signed in as the GitHub test account
/// authorizes the App, the suite's prover runs the token session with the
/// published credential as `client_secret` and the identity session through
/// the suite's notary, and both records are checked against the rules the
/// Platform Verifier applies. One authorization per run.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_github_authorization_yields_two_sessions_the_notary_attested() {
    let mut stack = Stack::attesting().await;
    let published = stack.published().await;
    let account = browser::github::Account::from_env("GH_TEST_ALICE");
    let redirect_uri = redirect_uri();
    let state = fresh_state();
    let code_verifier = s256(format!("{state}verifier"));
    let code_challenge = s256(&code_verifier);

    let grant = Grant::obtained(&browser::github::Authorization {
        account: &account,
        client_id: &published.client_id,
        redirect_uri: &redirect_uri,
        state: &state,
        code_challenge: &code_challenge,
    })
    .await;
    let code = grant.code.clone();
    grant.closed().await;

    let fields = github::TokenFields {
        client_id: &published.client_id,
        code: &code,
        redirect_uri: &redirect_uri,
        code_verifier: &code_verifier,
        client_secret: &published.credential,
    };
    let exchange = github::exchange(&stack.notary, github::token_request(&fields))
        .await
        .unwrap_or_else(|failed| panic!("the token session failed: {failed}"));
    eprintln!("token session: steps {:?}", exchange.session.steps);

    let bearer = &exchange.session.kept.value;
    assert_bearer(bearer);
    assert_eq!(exchange.blinder.len(), 16, "the bearer's blinder");
    assert_eq!(
        prover::recovered(&exchange.session.wire),
        stack.notary.pubkey(),
        "the token record was signed by this suite's notary"
    );
    let token_record = stack.notary.record().await;
    assert_eq!(
        token_record.encode().expect("the record encodes"),
        exchange.session.wire.attested_data,
        "the struct the notary signed is the bytes the prover received"
    );
    github::check_token(
        &token_record,
        exchange.session.sent_len,
        exchange.session.recv_len,
        &exchange.session.kept,
        &fields,
    );

    let identity = github::identity(&stack.notary, bearer)
        .await
        .unwrap_or_else(|failed| panic!("the identity session failed: {failed}"));
    eprintln!("identity session: steps {:?}", identity.session.steps);
    assert_eq!(
        prover::recovered(&identity.session.wire),
        stack.notary.pubkey(),
        "the identity record was signed by this suite's notary"
    );
    let identity_record = stack.notary.record().await;
    assert_eq!(
        identity_record.encode().expect("the record encodes"),
        identity.session.wire.attested_data
    );
    let (id, login) = github::check_identity(
        &identity_record,
        identity.session.sent_len,
        identity.session.recv_len,
        bearer,
        account.username(),
    );
    eprintln!("identity: an id of {} digits, login {login}", id.len());
}

/// A bearer X did not issue fails the identity session with X's own answer
/// (a `4xx`, `403 Forbidden` today) and the steps reached: a notary was
/// dialled, MPC-TLS completed against api.x.com and X answered. No account
/// is needed.
#[tokio::test(flavor = "multi_thread")]
async fn a_bearer_x_refuses_fails_the_identity_session() {
    stack::logging();
    let notary = Notary::attesting().await;
    let failed = x::identity(&notary, "not-a-bearer")
        .await
        .err()
        .expect("X refuses a bearer it did not issue");
    let message = failed.to_string();
    assert!(message.contains("API returned 4"), "{message}");
    assert!(
        message.contains("TlsHandshakeComplete"),
        "the session reached X before it failed: {message}"
    );
}

/// The X ceremony end to end, the bridge taking no part: Chrome signed in as
/// the X test account authorizes the app, the suite's prover runs the token
/// session and the identity session through the suite's notary, and both
/// records are checked against the rules the Platform Verifier applies. The
/// code lives thirty seconds, so everything that can be built before the
/// browser step is.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_x_authorization_yields_two_sessions_the_notary_attested() {
    stack::logging();
    let mut notary = Notary::attesting().await;
    let account = browser::x::Account::from_env("X_TEST_ALICE");
    let client_id = required("X_OAUTH_CLIENT_ID");
    let redirect_uri = required("LIBID_TEST_X_REDIRECT_URI");
    let state = fresh_state();
    let code_verifier = s256(format!("{state}verifier"));
    let code_challenge = s256(&code_verifier);

    let grant = Grant::obtained(&browser::x::Authorization {
        account: &account,
        client_id: &client_id,
        redirect_uri: &redirect_uri,
        state: &state,
        code_challenge: &code_challenge,
    })
    .await;
    let seen = Instant::now();

    let exchange = x::exchange(
        &notary,
        x::token_request(&client_id, &grant.code, &redirect_uri, &code_verifier),
    )
    .await
    .unwrap_or_else(|failed| {
        let late = if seen.elapsed() > X_CODE_LIFETIME {
            ", past the code's lifetime"
        } else {
            ""
        };
        panic!(
            "the token session failed {:?} after the code was seen{late}: {failed}",
            seen.elapsed()
        )
    });
    eprintln!(
        "token session: {:?} from the code to the record; steps {:?}",
        seen.elapsed(),
        exchange.session.steps
    );

    let bearer = &exchange.session.kept.value;
    assert_bearer(bearer);
    assert_eq!(exchange.blinder.len(), 16, "the bearer's blinder");
    assert_eq!(
        prover::recovered(&exchange.session.wire),
        notary.pubkey(),
        "the token record was signed by this suite's notary"
    );
    let token_record = notary.record().await;
    assert_eq!(
        token_record.encode().expect("the record encodes"),
        exchange.session.wire.attested_data,
        "the struct the notary signed is the bytes the prover received"
    );
    x::check_token(
        &token_record,
        exchange.session.sent_len,
        exchange.session.recv_len,
        &exchange.session.kept,
    );

    let identity = x::identity(&notary, bearer)
        .await
        .unwrap_or_else(|failed| panic!("the identity session failed: {failed}"));
    eprintln!("identity session: steps {:?}", identity.session.steps);
    assert_eq!(
        prover::recovered(&identity.session.wire),
        notary.pubkey(),
        "the identity record was signed by this suite's notary"
    );
    let identity_record = notary.record().await;
    assert_eq!(
        identity_record.encode().expect("the record encodes"),
        identity.session.wire.attested_data
    );
    let (id, username) = x::check_identity(
        &identity_record,
        identity.session.sent_len,
        identity.session.recv_len,
        bearer,
        account.username(),
    );
    eprintln!(
        "identity: an id of {} digits, username {username}",
        id.len()
    );

    grant.closed().await;
}

/// Sign in as the X test account through X's own pages and print the session
/// as the `X_TEST_ALICE_COOKIES` value. Run by name, ignored otherwise:
/// `BROWSER_HEAD=1 cargo test --features live-ceremony --test ceremony --
/// --ignored --nocapture a_fresh_x_session`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_fresh_x_session_is_exported_for_the_secret() {
    let account = browser::x::Account::from_env("X_TEST_ALICE");
    let authorization = browser::x::Authorization {
        account: &account,
        client_id: &required("X_OAUTH_CLIENT_ID"),
        redirect_uri: &required("LIBID_TEST_X_REDIRECT_URI"),
        state: "export",
        code_challenge: "",
    };
    println!(
        "X_TEST_ALICE_COOKIES={}",
        authorization.fresh_cookies().await
    );
}
