package main

const loginTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#0f766e">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-title" content="gatehub">
  <link rel="icon" type="image/png" href="/favicon.png">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <link rel="manifest" href="/site.webmanifest">
  <title>gatehub - sign in</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f7f8;
      --ink: #17201f;
      --muted: #64716f;
      --panel: #ffffff;
      --line: #d8dfdd;
      --teal: #0f766e;
      --red: #b42318;
      --shadow: 0 12px 34px rgba(21, 32, 31, .1);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      background: var(--bg); color: var(--ink);
      font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .login-card {
      width: min(360px, calc(100vw - 32px));
      background: var(--panel);
      border: 1px solid var(--line);
      border-top: 4px solid var(--teal);
      border-radius: 8px;
      padding: 26px;
      box-shadow: var(--shadow);
    }
    .login-title { font-size: 24px; font-weight: 750; margin-bottom: 8px; }
    .login-hint { color: var(--muted); line-height: 1.4; margin-bottom: 18px; }
    .login-btn {
      width: 100%; min-height: 42px;
      border: 1px solid var(--teal); border-radius: 6px;
      background: var(--teal); color: #fff; font: inherit; font-weight: 720; cursor: pointer;
    }
    .login-btn + .login-btn { margin-top: 10px; }
    .login-btn:hover { background: #0b5f59; }
    .login-btn:disabled { opacity: .55; cursor: progress; }
    .login-error { margin-top: 14px; color: var(--red); line-height: 1.35; }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="login-title">gatehub</div>
    <div class="login-hint" id="login-hint">Checking...</div>
    <button type="button" class="login-btn" id="login-btn" hidden>Authenticate</button>
    <button type="button" class="login-btn" id="register-btn" hidden>Register this device</button>
    <div class="login-error" id="login-error" hidden></div>
  </div>
<script>
(function() {
  const hint = document.getElementById("login-hint");
  const loginBtn = document.getElementById("login-btn");
  const regBtn = document.getElementById("register-btn");
  const errEl = document.getElementById("login-error");

  function showError(msg) { errEl.textContent = msg; errEl.hidden = false; }
  function clearError() { errEl.hidden = true; }
  function b64uToBuffer(b64u) {
    const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/").padEnd(b64u.length + (4 - b64u.length % 4) % 4, "=");
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
  }
  function bufferToB64u(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  function prepareAuthOptions(opts) {
    const pub = opts.publicKey || opts.response || opts;
    pub.challenge = b64uToBuffer(pub.challenge);
    if (pub.allowCredentials) pub.allowCredentials = pub.allowCredentials.map(c => ({ ...c, id: b64uToBuffer(c.id) }));
    return pub;
  }
  function prepareRegOptions(opts) {
    const pub = opts.publicKey || opts.response || opts;
    pub.challenge = b64uToBuffer(pub.challenge);
    pub.user.id = b64uToBuffer(pub.user.id);
    return pub;
  }
  function encodeCredential(cred) {
    const resp = cred.response;
    const out = { id: cred.id, rawId: bufferToB64u(cred.rawId), type: cred.type, response: { clientDataJSON: bufferToB64u(resp.clientDataJSON) } };
    if (resp.attestationObject) out.response.attestationObject = bufferToB64u(resp.attestationObject);
    if (resp.authenticatorData) out.response.authenticatorData = bufferToB64u(resp.authenticatorData);
    if (resp.signature) out.response.signature = bufferToB64u(resp.signature);
    if (resp.userHandle) out.response.userHandle = bufferToB64u(resp.userHandle);
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    return out;
  }
  async function post(url, body) {
    const r = await fetch(url, { method:"POST", headers:{ "Content-Type":"application/json" }, body:JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.detail || r.statusText);
    return j;
  }
  async function doLogin() {
    clearError(); loginBtn.disabled = true; loginBtn.textContent = "Waiting for passkey...";
    try {
      const opts = prepareAuthOptions(await post("/api/auth/login/begin", {}));
      const cred = await navigator.credentials.get({ publicKey: opts });
      await post("/api/auth/login/complete", encodeCredential(cred));
      window.location.href = "/";
    } catch (e) { showError(e.message || String(e)); }
    finally { loginBtn.disabled = false; loginBtn.textContent = "Authenticate"; }
  }
  async function doRegister() {
    clearError(); regBtn.disabled = true; regBtn.textContent = "Waiting for passkey...";
    try {
      const opts = prepareRegOptions(await post("/api/auth/register/begin", {}));
      const cred = await navigator.credentials.create({ publicKey: opts });
      await post("/api/auth/register/complete", encodeCredential(cred));
      window.location.href = "/";
    } catch (e) { showError(e.message || String(e)); }
    finally { regBtn.disabled = false; regBtn.textContent = "Register this device"; }
  }
  loginBtn.addEventListener("click", doLogin);
  regBtn.addEventListener("click", doRegister);
  (async function init() {
    try {
      const r = await fetch("/api/auth/status");
      const { registered } = await r.json();
      if (registered) { hint.textContent = "Use your passkey to continue."; loginBtn.hidden = false; }
      else { hint.textContent = "No passkey registered yet. Register this device to enable login."; regBtn.hidden = false; }
    } catch (e) { hint.textContent = "Could not reach server."; showError(String(e)); }
  })();
})();
</script>
</body>
</html>`
