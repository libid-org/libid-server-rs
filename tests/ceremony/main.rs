//! The live ceremony suite: real MPC-TLS sessions through a notary of this
//! suite, against real github.com. Built only with `--features
//! live-ceremony`; needs `GH_OAUTH_CLIENT_ID`, `GH_OAUTH_CLIENT_SECRET` and
//! `LIBID_TEST_REDIRECT_URI`, and for the success rung the test account
//! (`GH_TEST_ALICE_*`) and a Chrome. A missing variable fails the run.

#[path = "../common/bridge.rs"]
// Each suite uses its part of the module.
#[allow(dead_code)]
mod bridge;
mod browser;
mod notary;
mod stack;

use std::time::{
    Duration,
    Instant,
};

use base64::Engine;
use browser::{
    Account,
    AuthorizeRequest,
    Grant,
};
use libid_server_rs::fixtures::VERIFIER;
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

/// A refused authorization code is answered `400`, the caller's to fix. The
/// message exists only past the session: reaching it means a notary was
/// dialled, MPC-TLS completed against github.com and a transcript came back.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_code_is_answered_as_the_callers_to_fix() {
    let answer = Stack::attesting().await.exchange(SPENT_CODE).await;

    assert_eq!(answer.status, 400, "{}", answer.body);
    assert!(
        answer.message().contains("authorization code was refused"),
        "{}",
        answer.message()
    );
}

/// Credentials GitHub refuses are answered `502` with the generic message;
/// what GitHub said goes to the log. The client id is real: a placeholder id
/// is answered `404` by GitHub, a different path.
#[tokio::test(flavor = "multi_thread")]
async fn credentials_github_refuses_are_this_deployments_to_fix() {
    let answer = Stack::wrong_secret().await.exchange(SPENT_CODE).await;

    assert_eq!(answer.status, 502, "{}", answer.body);
    assert_eq!(answer.message(), "token exchange failed");
}

/// A notary that accepts the connection and never speaks is answered `502`
/// when `SESSION_TIMEOUT` expires. As slow as the budget it asserts.
#[tokio::test(flavor = "multi_thread")]
async fn a_notary_that_never_speaks_is_bounded_by_the_session_budget() {
    let started = Instant::now();
    let answer = Stack::silent_notary().await.exchange(SPENT_CODE).await;

    assert_eq!(answer.status, 502, "{}", answer.body);
    assert!(
        started.elapsed() >= Duration::from_secs(120),
        "answered after {:?}, before the session budget",
        started.elapsed()
    );
}

/// The success path: a real authorization, a bearer, and an attestation that
/// recovers to the notary that signed it. One authorization per run.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_authorization_yields_a_bearer_the_notary_attested() {
    let stack = Stack::attesting().await;
    let account = Account::from_env("GH_TEST_ALICE");
    let state = format!(
        "{:x}{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_nanos()
    );
    let code_challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER));
    let grant = Grant::obtained(
        &account,
        &AuthorizeRequest {
            client_id: &required("GH_OAUTH_CLIENT_ID"),
            redirect_uri: &redirect_uri(),
            state: &state,
            code_challenge: &code_challenge,
        },
    )
    .await;

    let answer = stack.exchange(&grant.code).await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let body: serde_json::Value =
        serde_json::from_str(&answer.body).expect("a JSON response");
    let b64 = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(v.as_str().expect("a base64 string"))
            .expect("unpadded url-safe base64")
    };

    // The bearer is the string GitHub issued, not base64.
    let bearer = body["accessToken"].as_str().expect("a bearer");
    assert!(!bearer.is_empty());

    let attested = b64(&body["tokenAttestation"]["attestedData"]);
    let signature = b64(&body["tokenAttestation"]["signature"]);
    let opening = b64(&body["bearerOpening"]);
    assert!(!attested.is_empty(), "the notary attested something");
    assert_eq!(signature.len(), 65, "a notary signature");
    assert_eq!(opening.len(), 16, "the bearer's blinder");

    // The signature is over keccak256(attestedData) and recovers to this
    // deployment's notary.
    let recovered =
        libid_crypto::recover_eth_claim(&signature, &libid_crypto::keccak256(&attested))
            .expect("a signature over the record it accompanies");
    assert_eq!(
        libid_crypto::pubkey_to_hex(&recovered),
        stack.notary_pubkey(),
        "the record was signed by this deployment's notary"
    );
}

/// Signs in as the test account and prints the `GH_TEST_ALICE_COOKIES` value
/// for the next runs. Run by hand:
/// `cargo test --features live-ceremony --test ceremony -- --ignored --nocapture a_fresh_session`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_fresh_session_is_exported_for_the_secret() {
    stack::logging();
    let account = Account::from_env("GH_TEST_ALICE");
    println!("GH_TEST_ALICE_COOKIES={}", account.fresh_cookies().await);
}
