// The callback clearing bootstrap. Deployment-generated; its exact text is
// hashed into this document's Content-Security-Policy.
//
// One input mode: the OAuth platform's return to the registered redirect URI.
// Everything below happens before rendering, storage, error reporting, module
// import or any other network use -- copy the input, bound it, clear it, then
// decide. Nothing from the URL reaches the document: an error that echoed the
// return would put the credential back on the page it was just cleared from.
const ccdpOrigin = __CCDP_ORIGIN__;
const defaultInputs = deepFreeze([__ORIGINS__, ccdpOrigin]);
const supportedCCDPVersions = Object.freeze(__VERSIONS__);
const callbackInputOverrides = deepFreeze(__OVERRIDES__);
const MAX_OAUTH_RETURN_BYTES = 32768;

function deepFreeze(value) {
  if (value !== null && typeof value === 'object') {
    for (const key of Object.getOwnPropertyNames(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}

function fail() {
  const mount = document.getElementById('libid-root');
  if (mount) mount.textContent = 'This authorization link cannot be used.';
}

// 1. Bound and copy the raw query and fragment, leading delimiters included.
const query = location.search;
const fragment = location.hash;
const oversized = query.length + fragment.length > MAX_OAUTH_RETURN_BYTES;

// 2. Clear both, keeping the same path. An oversized input is discarded, not
//    truncated: a truncated OAuth return is a different return.
history.replaceState(null, '', location.pathname);
if (oversized) {
  fail();
} else {
  // 3. Only a provider return with exactly one routing `state`. This document
  //    parses no platform field, classifies no approval or denial, and does
  //    not read the fragment -- Google's credential lives there and is not
  //    ours to read; the module receives it unchanged.
  const states = new URLSearchParams(query).getAll('state');
  // 4. Only the `v<version>.` prefix, and only a version on the closed list.
  const match = states.length === 1 ? /^v(\d+)\./.exec(states[0]) : null;
  const version = match ? Number(match[1]) : NaN;

  if (!supportedCCDPVersions.includes(version)) {
    fail();
  } else {
    // 5. The version's input override, or the current default tuple.
    // 6. Frozen, so the module receives what the deployment set and nothing
    //    a later script could have reached in to change.
    const locationInput = deepFreeze({ query, fragment });
    const inputs = callbackInputOverrides[version] ?? defaultInputs;
    // 7. Import the one module this version names, once. A root that will not
    //    load is terminal for this document -- the browser caches the failed
    //    module-map entry, so a fresh document is the only retry.
    const moduleUrl = new URL(`/ccdp/v${version}/callback.js`, ccdpOrigin).href;
    import(moduleUrl).then(
      (callback) => callback.startCallback(locationInput, ...inputs),
      fail,
    );
  }
}
