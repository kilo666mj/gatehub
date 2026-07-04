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
    <div class="login-hint">Sign in with your Pocket ID account to continue.</div>
    <button type="button" class="login-btn" id="login-btn">Sign in with Pocket ID</button>
    <div class="login-error" id="login-error" hidden></div>
  </div>
<script>
(function() {
  const errEl = document.getElementById("login-error");
  const err = new URLSearchParams(window.location.search).get("error");
  if (err) { errEl.textContent = err; errEl.hidden = false; }
  const btn = document.getElementById("login-btn");
  btn.addEventListener("click", function() {
    btn.disabled = true; btn.textContent = "Redirecting...";
    window.location.href = "/api/auth/login/start";
  });
})();
</script>
</body>
</html>`
