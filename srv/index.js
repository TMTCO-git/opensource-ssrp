import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";

const app = new Hono();

// ============================================================
// CONFIG
// ============================================================
// This portal lives on one hostname only.
const PORTAL_HOST = "ssrp.tmtcoau.com";
const BASE_URL = `https://${PORTAL_HOST}`;

const BRAND = "TMTCo";
const SUPPORT_URL = "https://tmtcoau.com/contact";

const SESSION_COOKIE = "ssrp_sid";
const SESSION_TTL = 60 * 20; // 20 minute idle session
const QR_REUSE_MS = 4 * 60 * 1000; // reuse a Verified ID QR code for up to 4 minutes

const PASSWORD_MIN = 6;
const PASSWORD_MAX = 256;

// User.ReadWrite is required for POST /me/changePassword.
const GRAPH_SCOPES = "openid profile email User.Read User.ReadWrite";
const GRAPH_ME_URL =
  "https://graph.microsoft.com/v1.0/me?$select=id,displayName,userPrincipalName,mail,accountEnabled";

// Verified ID defaults - override with env vars (VC_AUTHORITY, VC_TYPE, VC_ISSUER, ...)
const VC_AUTHORITY_DEFAULT =
  "did:web:verifiedid.entra.microsoft.com:f1011f75-0d96-4d08-b8d4-6c79c851f9ba:f5674475-f43e-b35b-dcc6-5d3c3efe6441";
const VC_TYPE_DEFAULT = "VerifiedEmployee";
const VC_RESOURCE_SCOPE = "3db474b9-6a0c-4840-96ac-1fceb342124f/.default";

const ERROR_MESSAGES = {
  signin: "Microsoft sign-in was cancelled or could not be completed. Please try again.",
  expired: "Your session has expired. Please start again.",
  verify: "Verified ID did not confirm your identity. Please try again.",
  identity: "The Verified ID credential does not belong to the account you signed in with.",
};

const MS_LOGO = `<svg viewBox="0 0 21 21" width="20" height="20" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
<rect x="1" y="1" width="9" height="9" fill="#f25022"/>
<rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
<rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
<rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
</svg>`;

// ============================================================
// STYLES - design tokens and components taken from the TMTCo site
// ============================================================
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap');

:root {
  --bg:#0b0e14; --surface:#12161f; --surface2:#1a1f2e; --border:#242938;
  --accent:#3b82f6; --accent2:#60a5fa; --text:#e8eaf0; --muted:#8892a4;
  --heading:'Syne',sans-serif; --body:'DM Sans',sans-serif;
  --radius:14px; --transition:.25s cubic-bezier(.4,0,.2,1);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh;display:flex;flex-direction:column}
a{color:var(--accent2);text-decoration:none;transition:color var(--transition)}
a:hover{color:#fff}

/* NAV */
nav{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(11,14,20,.92);
backdrop-filter:blur(12px);border-bottom:1px solid var(--border);
padding:0 2rem;height:64px;display:flex;align-items:center;justify-content:space-between;gap:1rem}
.nav-logo{font-family:var(--heading);font-weight:800;font-size:1.15rem;letter-spacing:-0.02em;color:#fff;display:flex;align-items:center;gap:.55rem}
.nav-logo:hover{color:#fff}
.nav-logo .dot{width:8px;height:8px;border-radius:50%;background:var(--accent);display:inline-block;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.4)}}
.nav-actions{display:flex;gap:.6rem;align-items:center}
.nav-actions form{display:inline-flex;margin:0}

/* PAGE SHELL */
.page{flex:1;display:flex;align-items:center;justify-content:center;padding:6.5rem 1.5rem 3rem;position:relative;overflow:hidden}
.page::before{content:'';position:absolute;inset:0;
background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);
background-size:48px 48px;mask-image:radial-gradient(ellipse 80% 60% at 50% 40%,black 30%,transparent 100%);opacity:.45;pointer-events:none}
.page::after{content:'';position:absolute;top:30%;left:50%;transform:translate(-50%,-50%);width:600px;height:600px;
background:radial-gradient(circle,rgba(59,130,246,.18) 0%,transparent 70%);pointer-events:none}

/* CARD */
.card{position:relative;z-index:1;background:var(--surface);border:1px solid var(--border);
border-radius:20px;padding:2.6rem 2.4rem;width:100%;max-width:460px;animation:fadeUp .4s both}
.card.wide{max-width:540px}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.badge{display:flex;width:fit-content;margin:0 auto 1.2rem;align-items:center;gap:.4rem;background:rgba(59,130,246,.12);
border:1px solid rgba(59,130,246,.3);border-radius:100px;padding:.3rem .85rem;font-size:.75rem;font-weight:500;
color:var(--accent2);letter-spacing:.04em}
.card h2{font-family:var(--heading);font-size:1.5rem;font-weight:700;color:#fff;letter-spacing:-0.02em;text-align:center;margin-bottom:.5rem}
.lead{color:var(--muted);font-size:.92rem;text-align:center;margin-bottom:1.6rem}
.lead strong{color:var(--text);font-weight:500}
.login-note{margin-top:1.2rem;font-size:.78rem;color:var(--muted);text-align:center}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;padding:.7rem 1.5rem;border-radius:10px;
font-size:.9rem;font-weight:500;cursor:pointer;transition:all var(--transition);border:none;font-family:var(--body);
text-decoration:none;width:100%}
.btn-sm{width:auto;padding:.45rem .9rem;font-size:.82rem}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2);color:#fff;transform:translateY(-2px);box-shadow:0 8px 24px rgba(59,130,246,.35)}
.btn-ghost{background:var(--surface2);color:var(--text);border:1px solid var(--border);width:auto}
.btn-ghost:hover{border-color:var(--accent);color:var(--accent2);transform:translateY(-2px)}
.ms-login-btn{display:flex;align-items:center;justify-content:center;gap:.75rem;width:100%;padding:.85rem 1.5rem;
background:#fff;color:#1a1a1a;border:none;border-radius:10px;font-size:.95rem;font-weight:500;font-family:var(--body);
text-decoration:none;cursor:pointer;transition:all var(--transition)}
.ms-login-btn:hover{background:#f0f0f0;color:#1a1a1a;transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.3)}
.ms-login-btn svg{flex-shrink:0}
.divider-line{display:flex;align-items:center;gap:.75rem;margin:1.2rem 0;color:var(--muted);font-size:.8rem}
.divider-line::before,.divider-line::after{content:"";height:1px;background:var(--border);flex:1}

/* STEPPER */
.steps{list-style:none;display:flex;justify-content:space-between;gap:.5rem;margin-bottom:1.8rem}
.steps li{flex:1;display:flex;flex-direction:column;align-items:center;gap:.4rem;font-size:.72rem;color:var(--muted);text-align:center}
.step-num{width:28px;height:28px;border-radius:50%;border:1px solid var(--border);display:flex;align-items:center;
justify-content:center;font-size:.8rem;font-weight:600;background:var(--surface2)}
.steps li.active{color:var(--text)}
.steps li.active .step-num{border-color:var(--accent);background:rgba(59,130,246,.15);color:var(--accent2)}
.steps li.done .step-num{background:rgba(74,222,128,.12);border-color:rgba(74,222,128,.4);color:#4ade80}

/* ALERTS */
.error-box{margin:0 0 1.2rem;padding:.75rem 1rem;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);
border-radius:8px;color:#f87171;font-size:.85rem}
.success-box{margin:0 0 1.2rem;padding:.9rem 1rem;background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.3);
border-radius:8px;color:#4ade80;font-size:.9rem}
.notice{padding:.75rem 1rem;background:rgba(59,130,246,.08);border-left:3px solid var(--accent);border-radius:0 8px 8px 0;
font-size:.85rem;color:var(--text)}

/* VERIFIED ID */
.vc-qr-wrap{background:#fff;border-radius:10px;padding:1rem;display:flex;align-items:center;justify-content:center;
min-height:256px;min-width:256px;margin:0 auto 1.2rem;max-width:max-content}
.vc-qr-wrap img{width:240px;height:240px;display:block}
.vc-status{font-size:.88rem;color:var(--muted);margin-top:1rem;text-align:center}
.vc-status.ok{color:#4ade80;font-weight:500}
.vc-status.err{color:#f87171;font-weight:500}
.vc-actions{display:flex;flex-direction:column;gap:.6rem;margin-top:1.2rem}

/* PASSWORD FORM */
.field{margin-top:1rem}
.field label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:.4rem}
.field input{width:100%;padding:.75rem 1rem;border-radius:10px;border:1px solid var(--border);background:var(--surface2);
color:var(--text);font-family:var(--body);font-size:.92rem}
.field input:focus{outline:none;border-color:var(--accent)}
.rules{list-style:none;margin:1.1rem 0 1.4rem;font-size:.8rem;color:var(--muted);display:grid;
grid-template-columns:1fr 1fr;gap:.35rem .9rem}
.rules li::before{content:'\\25CB';color:var(--border);margin-right:.35rem}
.rules li.ok{color:#4ade80}
.rules li.ok::before{content:'\\2713';color:#4ade80}
.form-actions{display:flex;flex-direction:column;gap:.6rem}

/* FOOTER */
.divider{max-width:1100px;margin:0 auto;border:none;border-top:1px solid var(--border)}
footer{max-width:1100px;margin:0 auto;padding:2rem 2rem 3rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem}
footer p{color:var(--muted);font-size:.85rem}
.footer-links{display:flex;gap:1.5rem;flex-wrap:wrap}
.footer-links a{color:var(--muted);font-size:.85rem}
.footer-links a:hover{color:var(--text)}

@media(max-width:600px){
  nav{padding:0 1rem}
  .card{padding:2rem 1.4rem}
  .rules{grid-template-columns:1fr}
}
`;

// Client-side script: live password checklist (server still enforces every rule).
// String.raw keeps the regex escapes intact.
const CLIENT_JS = String.raw`
(function () {
  var pw = document.getElementById('newPassword');
  var confirmEl = document.getElementById('confirmPassword');
  if (!pw || !confirmEl) return;
  var rules = {
    len: function (v) { return v.length >= 6; },
    upper: function (v) { return /[A-Z]/.test(v); },
    lower: function (v) { return /[a-z]/.test(v); },
    num: function (v) { return /\d/.test(v); },
    sym: function (v) { return /[^A-Za-z0-9\s]/.test(v); },
    match: function (v) { return v.length > 0 && v === confirmEl.value; }
  };
  function update() {
    var v = pw.value;
    document.querySelectorAll('[data-rule]').forEach(function (li) {
      li.classList.toggle('ok', !!rules[li.getAttribute('data-rule')](v));
    });
  }
  pw.addEventListener('input', update);
  confirmEl.addEventListener('input', update);
  update();
})();
`;

// Client-side script: waits for Verified ID approval, then continues the flow.
const VERIFY_POLL_JS = String.raw`
(function () {
  var status = document.getElementById('vcStatus');
  var deadline = Date.now() + 4 * 60 * 1000;
  function poll() {
    if (Date.now() > deadline) {
      status.textContent = 'This request expired. Refresh the page to try again.';
      status.className = 'vc-status err';
      return;
    }
    fetch('/verify/status', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.error) { window.location.href = '/?error=expired'; return; }
        if (d.status === 'presentation_verified') {
          status.textContent = 'Verified. Continuing...';
          status.className = 'vc-status ok';
          window.location.href = '/verify/complete';
          return;
        }
        if (d.status === 'presentation_error') { window.location.href = '/?error=verify'; return; }
        if (d.status === 'request_retrieved') {
          status.textContent = 'Authenticator opened. Approve the request on your phone...';
        }
        setTimeout(poll, 2000);
      })
      .catch(function () { setTimeout(poll, 3000); });
  }
  poll();
})();
`;

// ============================================================
// HELPERS
// ============================================================
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function safeJson(raw) {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function missingConfig(env) {
  return ["TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "VC_CALLBACK_KEY"].filter(
    (k) => !env[k] || !String(env[k]).trim()
  );
}

function stepper(current) {
  const steps = ["Microsoft sign-in", "Verified ID", "New password"];
  const items = steps
    .map((label, i) => {
      const n = i + 1;
      const cls = n < current ? "done" : n === current ? "active" : "";
      const num = n < current ? "&#10003;" : String(n);
      return `<li class="${cls}"><span class="step-num">${num}</span><span>${label}</span></li>`;
    })
    .join("");
  return `<ol class="steps" aria-label="Progress">${items}</ol>`;
}

function errorBox(message) {
  return message ? `<div class="error-box" role="alert">${escapeHtml(message)}</div>` : "";
}

function layout({ title, body, signedIn }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<meta name="robots" content="noindex,nofollow"/>
<title>${escapeHtml(title)} - ${BRAND}</title>
<link rel="icon" type="image/png" href="https://tmtcoau.com/favicon/favicon-96x96.png"/>
<link rel="icon" type="image/svg+xml" href="https://tmtcoau.com/favicon/favicon.svg"/>
<link rel="apple-touch-icon" sizes="180x180" href="https://tmtcoau.com/favicon/apple-touch-icon.png"/>
<style>${CSS}</style>
</head>
<body>
<nav>
  <a href="/" class="nav-logo"><span class="dot"></span>${BRAND}</a>
  <div class="nav-actions">
    <a class="btn btn-ghost btn-sm" href="${escapeHtml(SUPPORT_URL)}" target="_blank" rel="noopener">Help</a>
    ${
      signedIn
        ? `<form method="post" action="/"><input type="hidden" name="action" value="logout"/><button class="btn btn-ghost btn-sm" type="submit">Sign out</button></form>`
        : ""
    }
  </div>
</nav>

<main class="page">${body}</main>

<hr class="divider"/>
<footer>
  <p>&copy; ${new Date().getFullYear()} TMTCo &mdash; All rights reserved.</p>
  <p>ABN: 37 546 247 840</p>
  <div class="footer-links">
    <a href="https://tmtcoau.com/tos">Terms of Service</a>
    <a href="https://tmtcoau.com/privacy">Privacy</a>
    <a href="https://tmtcoau.com/contact">Contact</a>
  </div>
</footer>
</body>
</html>`;
}

function page(c, { title, body, signedIn = false, status = 200, script = "" }) {
  const html = layout({
    title,
    body: script ? `${body}<script>${script}</script>` : body,
    signedIn,
  });
  return c.html(html, status);
}

// ============================================================
// SESSION HELPERS (KV, server-side; cookie only carries the id)
// ============================================================
async function getSession(c) {
  const sid = getCookie(c, SESSION_COOKIE);
  if (!sid) return { sid: null, data: null };
  const data = safeJson(await c.env.SESSIONS.get(`session:${sid}`));
  return data ? { sid, data } : { sid: null, data: null };
}

async function saveSession(c, sid, data) {
  await c.env.SESSIONS.put(`session:${sid}`, JSON.stringify(data), { expirationTtl: SESSION_TTL });
}

async function startSession(c, data) {
  const sid = crypto.randomUUID();
  await saveSession(c, sid, data);
  setCookie(c, SESSION_COOKIE, sid, {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: SESSION_TTL,
  });
  return sid;
}

async function endSession(c) {
  const sid = getCookie(c, SESSION_COOKIE);
  if (sid) await c.env.SESSIONS.delete(`session:${sid}`).catch(() => {});
  deleteCookie(c, SESSION_COOKIE, { path: "/" });
}

// ============================================================
// MICROSOFT GRAPH
// ============================================================
async function graphMe(accessToken) {
  const r = await fetch(GRAPH_ME_URL, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!r.ok) throw new Error(`Graph /me failed: ${r.status}`);
  return r.json();
}

async function changeGraphPassword(accessToken, currentPassword, newPassword) {
  const r = await fetch("https://graph.microsoft.com/v1.0/me/changePassword", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ currentPassword, newPassword }),
  });
  if (r.ok) return { ok: true };
  if (r.status === 401) return { ok: false, expired: true };

  // Never echo Graph's message back (it can reflect policy details); map to plain language.
  const body = await r.json().catch(() => null);
  const code = body?.error?.code || "";
  if (code === "InvalidPassword") {
    return { ok: false, message: "Your current password is incorrect." };
  }
  console.error("changePassword failed:", r.status, code);
  return {
    ok: false,
    message:
      "Microsoft did not accept this new password. It may not meet your organisation's password policy or may be too similar to a recent password.",
  };
}

// ============================================================
// PASSWORD RULES
// ============================================================
const LEET = { 0: "o", 1: "l", "!": "i", "|": "l", 3: "e", 4: "a", "@": "a", 5: "s", $: "s", 7: "t" };

// Reduce a password to its letter "core" so that e.g. Summer2024! and Summer!1 compare as the same word.
function passwordCore(s) {
  return s
    .toLowerCase()
    .replace(/[01!|3457@$]/g, (ch) => LEET[ch])
    .replace(/[^a-z]/g, "");
}

function levenshtein(a, b) {
  const row = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return row[b.length];
}

function looksSimilar(oldPw, newPw) {
  const rawOld = oldPw.toLowerCase();
  const rawNew = newPw.toLowerCase();
  if (rawOld === rawNew) return true;

  const a = passwordCore(oldPw) || rawOld.replace(/\s/g, "");
  const b = passwordCore(newPw) || rawNew.replace(/\s/g, "");
  if (a === b) return true;

  const shorter = Math.min(a.length, b.length);
  if (shorter >= 4 && (a.includes(b) || b.includes(a))) return true;

  const threshold = Math.max(2, Math.floor(Math.max(a.length, b.length) * 0.3));
  return levenshtein(a, b) <= threshold;
}

function validatePasswordChange({ current, next, confirm }) {
  if (!current) return "Enter your current password.";
  if (!next) return "Enter a new password.";
  if (next !== confirm) return "The two new passwords do not match.";
  if (next.length < PASSWORD_MIN) return `The new password must be at least ${PASSWORD_MIN} characters long.`;
  if (next.length > PASSWORD_MAX) return `The new password must be no more than ${PASSWORD_MAX} characters.`;
  if (!/[a-z]/.test(next)) return "The new password needs at least one lowercase letter.";
  if (!/[A-Z]/.test(next)) return "The new password needs at least one uppercase letter.";
  if (!/\d/.test(next)) return "The new password needs at least one number.";
  if (!/[^A-Za-z0-9\s]/.test(next)) return "The new password needs at least one symbol.";
  if (next === current) return "The new password must be different from your current password.";
  if (looksSimilar(current, next)) {
    return "The new password is too similar to your current password. Choose something noticeably different.";
  }
  return null;
}

// ============================================================
// VERIFIED ID (second factor)
// ============================================================
async function getVerifiedIdAppToken(env) {
  const res = await fetch(`https://login.microsoftonline.com/${env.TENANT_ID}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.CLIENT_ID,
      client_secret: env.CLIENT_SECRET,
      grant_type: "client_credentials",
      scope: VC_RESOURCE_SCOPE,
    }),
  });
  if (!res.ok) {
    console.error("Verified ID app token request failed:", res.status);
    return null;
  }
  const data = await res.json().catch(() => null);
  return data?.access_token || null;
}

async function createPresentationRequest(env) {
  const token = await getVerifiedIdAppToken(env);
  if (!token) return null;

  const state = crypto.randomUUID();
  const verifierAuthority = env.VC_VERIFIER_AUTHORITY || env.VC_AUTHORITY || VC_AUTHORITY_DEFAULT;
  const acceptedIssuer = env.VC_ISSUER || env.VC_AUTHORITY || VC_AUTHORITY_DEFAULT;
  const credentialType = env.VC_TYPE || VC_TYPE_DEFAULT;

  const res = await fetch(
    "https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/createPresentationRequest",
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        authority: verifierAuthority,
        includeQRCode: true,
        includeReceipt: false,
        registration: {
          clientName: env.VC_VERIFIER_CLIENT_NAME || `${BRAND} Password Reset`,
          purpose: "Confirm your identity before changing your password",
        },
        callback: {
          url: `${BASE_URL}/verify/callback`,
          state,
          headers: { "api-key": env.VC_CALLBACK_KEY },
        },
        requestedCredentials: [
          {
            type: credentialType,
            purpose: "Prove that you are a verified TMTCo employee",
            acceptedIssuers: [acceptedIssuer],
            configuration: { validation: { allowRevoked: false, validateLinkedDomain: true } },
          },
        ],
      }),
    }
  );

  const body = await res.json().catch(() => null);
  if (!res.ok || !body?.url) {
    console.error("Verified ID createPresentationRequest failed:", res.status);
    return null;
  }
  const qrCode = typeof body.qrCode === "string" && body.qrCode.startsWith("data:image/") ? body.qrCode : "";
  return { state, url: body.url, qrCode };
}

// Reuse a live request for this session so refreshing the page does not spam new QR codes.
async function getVerifiedIdRequest(c, sid, data) {
  if (data.vc_state) {
    const rec = safeJson(await c.env.SESSIONS.get(`vclogin:${data.vc_state}`));
    if (rec && rec.sid === sid && rec.status === "pending" && Date.now() - rec.createdAt < QR_REUSE_MS) {
      return rec;
    }
  }

  const created = await createPresentationRequest(c.env);
  if (!created) return null;

  const rec = { sid, status: "pending", url: created.url, qrCode: created.qrCode, createdAt: Date.now() };
  await c.env.SESSIONS.put(`vclogin:${created.state}`, JSON.stringify(rec), { expirationTtl: 600 });
  data.vc_state = created.state;
  await saveSession(c, sid, data);
  return rec;
}

// Accept only a credential from the expected issuer and type, and read the email claim from it.
function getVerifiedIdentity(env, credentials) {
  if (!Array.isArray(credentials) || !credentials.length) return null;
  const expectedType = env.VC_TYPE || VC_TYPE_DEFAULT;
  const expectedIssuer = env.VC_ISSUER || env.VC_AUTHORITY || VC_AUTHORITY_DEFAULT;

  const credential = credentials.find((vc) => {
    const types = Array.isArray(vc.type) ? vc.type : [];
    const revocationOk = !vc.credentialState || vc.credentialState.revocationStatus === "VALID";
    return vc.issuer === expectedIssuer && types.includes(expectedType) && revocationOk;
  });
  if (!credential) return null;

  const claims = credential.claims && typeof credential.claims === "object" ? credential.claims : {};
  const email = String(claims.mail || claims.userPrincipalName || "").trim();
  return email ? { email } : null;
}

// ============================================================
// MIDDLEWARE - single hostname, security headers
// ============================================================
app.use("*", async (c, next) => {
  const url = new URL(c.req.url);
  if (c.env.DEV_MODE !== "true" && url.hostname !== PORTAL_HOST) {
    return c.redirect(`${BASE_URL}${url.pathname}${url.search}`, 301);
  }
  c.header("X-Frame-Options", "DENY");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "same-origin");
  c.header("Cache-Control", "no-store");
  await next();
});

// Anything that is not a known route goes back to the one page.
app.notFound((c) => c.redirect("/"));

// ============================================================
// THE ONE PAGE - GET shows the current step, POST handles actions
// ============================================================
app.get("/", async (c) => {
  const missing = missingConfig(c.env);
  if (missing.length) {
    console.error("SSPR missing config:", missing.join(", "));
    return page(c, {
      title: "Password Reset",
      status: 500,
      body: `<div class="card"><div class="badge">Unavailable</div><h2>Portal unavailable</h2>
<p class="lead">This service is temporarily unavailable. Please contact IT support.</p></div>`,
    });
  }

  const { sid, data } = await getSession(c);
  const error = ERROR_MESSAGES[c.req.query("error")] || "";

  // Success screen after a completed reset (session already ended).
  if (!data && c.req.query("done") === "1") {
    return page(c, {
      title: "Password changed",
      body: `<div class="card">
  <div class="badge">Complete</div>
  <h2>Password changed</h2>
  <p class="lead">Your password has been updated. Use your new password the next time you sign in.</p>
  <div class="success-box">Your change was accepted by Microsoft.</div>
  <a class="btn btn-primary" href="/">Reset another password</a>
</div>`,
    });
  }

  // Step 1: not signed in.
  if (!data || !data.msAuthed) {
    return page(c, {
      title: "Password Reset",
      body: `<div class="card">
  <div class="badge">Self-service password reset</div>
  <h2>Reset your password</h2>
  <p class="lead">Sign in with your work Microsoft account, confirm your identity with Verified ID, then choose a new password.</p>
  ${stepper(1)}
  ${errorBox(error)}
  <a class="ms-login-btn" href="/auth/login">${MS_LOGO}<span>Sign in with Microsoft</span></a>
  <p class="login-note">All steps are required. This portal will never ask for your password until you are verified.</p>
</div>`,
    });
  }

  // Step 2: Microsoft signed in, waiting for Verified ID.
  if (!data.verified) {
    const vc = await getVerifiedIdRequest(c, sid, data);
    const qr = vc?.qrCode
      ? `<div class="vc-qr-wrap"><img src="${escapeHtml(vc.qrCode)}" alt="Scan with Microsoft Authenticator"/></div>`
      : `<p class="vc-status err">Verified ID could not start. Please try again later.</p>`;
    const openLink = vc?.url
      ? `<a class="btn btn-primary" href="${escapeHtml(vc.url)}">Open in Microsoft Authenticator</a>`
      : "";

    return page(c, {
      title: "Verify your identity",
      script: VERIFY_POLL_JS,
      body: `<div class="card wide">
  <div class="badge">Step 2 of 3</div>
  <h2>Verify it's you</h2>
  <p class="lead">Signed in as <strong>${escapeHtml(data.email || data.upn || data.name)}</strong>. Approve your Verified ID credential in Microsoft Authenticator, or scan the code below.</p>
  ${stepper(2)}
  ${errorBox(error)}
  ${qr}
  <div class="vc-actions">
    ${openLink}
    <p id="vcStatus" class="vc-status">Waiting for your Verified ID...</p>
  </div>
  <form method="post" action="/" class="vc-actions">
    <input type="hidden" name="action" value="logout"/>
    <button class="btn btn-ghost" type="submit" style="width:100%">Cancel</button>
  </form>
</div>`,
    });
  }

  // Step 3: verified - enter current password and new password twice.
  return renderResetForm(c, data, error, 200);
});

function renderResetForm(c, data, error, status) {
  return page(c, {
    title: "Change password",
    status,
    script: CLIENT_JS,
    signedIn: true,
    body: `<div class="card wide">
  <div class="badge">Step 3 of 3</div>
  <h2>Choose a new password</h2>
  <p class="lead">Verified as <strong>${escapeHtml(data.email || data.upn || data.name)}</strong>. Enter your current password, then your new password twice.</p>
  ${stepper(3)}
  ${errorBox(error)}
  <form method="post" action="/" autocomplete="on" novalidate>
    <input type="hidden" name="action" value="reset"/>

    <div class="field">
      <label for="currentPassword">Current password</label>
      <input id="currentPassword" name="currentPassword" type="password" autocomplete="current-password" required/>
    </div>

    <div class="field">
      <label for="newPassword">New password</label>
      <input id="newPassword" name="newPassword" type="password" autocomplete="new-password" required/>
    </div>

    <div class="field">
      <label for="confirmPassword">Confirm new password</label>
      <input id="confirmPassword" name="confirmPassword" type="password" autocomplete="new-password" required/>
    </div>

    <ul class="rules">
      <li data-rule="len">At least ${PASSWORD_MIN} characters</li>
      <li data-rule="upper">One uppercase letter</li>
      <li data-rule="lower">One lowercase letter</li>
      <li data-rule="num">One number</li>
      <li data-rule="sym">One symbol</li>
      <li data-rule="match">New passwords match</li>
    </ul>

    <div class="form-actions">
      <button class="btn btn-primary" type="submit">Change password</button>
    </div>
  </form>

  <p class="login-note">The new password must not be similar to your current one. You will be signed out after the change.</p>
</div>`,
  });
}

app.post("/", async (c) => {
  // Basic CSRF guard on top of SameSite=Lax cookies.
  const origin = c.req.header("Origin");
  if (origin && origin !== BASE_URL) return c.text("Forbidden", 403);

  const form = await c.req.parseBody().catch(() => ({}));
  const action = typeof form.action === "string" ? form.action : "";
  const { sid, data } = await getSession(c);

  if (action === "logout") {
    await endSession(c);
    return c.redirect("/");
  }

  if (action !== "reset" || !data?.msAuthed || !data?.verified) {
    return c.redirect("/");
  }

  const current = typeof form.currentPassword === "string" ? form.currentPassword : "";
  const next = typeof form.newPassword === "string" ? form.newPassword : "";
  const confirm = typeof form.confirmPassword === "string" ? form.confirmPassword : "";

  const problem = validatePasswordChange({ current, next, confirm });
  if (problem) return renderResetForm(c, data, problem, 400);

  const result = await changeGraphPassword(data.access_token, current, next);

  if (result.ok) {
    await endSession(c); // sign out after a successful change
    return c.redirect("/?done=1");
  }
  if (result.expired) {
    await endSession(c);
    return c.redirect("/?error=expired");
  }
  return renderResetForm(c, data, result.message, 400);
});

// ============================================================
// MICROSOFT SIGN-IN (step 1)
// ============================================================
app.get("/auth/login", async (c) => {
  if (missingConfig(c.env).length) return c.redirect("/?error=signin");

  const state = crypto.randomUUID();
  await c.env.SESSIONS.put(`oauth:${state}`, "1", { expirationTtl: 300 });

  const params = new URLSearchParams({
    client_id: c.env.CLIENT_ID,
    response_type: "code",
    redirect_uri: `${BASE_URL}/auth/callback`,
    response_mode: "query",
    scope: GRAPH_SCOPES,
    state,
    prompt: "select_account",
  });
  return c.redirect(`https://login.microsoftonline.com/${c.env.TENANT_ID}/oauth2/v2.0/authorize?${params}`);
});

app.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  if (c.req.query("error") || !code || !state) return c.redirect("/?error=signin");

  const stateKey = `oauth:${state}`;
  const stored = await c.env.SESSIONS.get(stateKey);
  if (!stored) return c.redirect("/?error=signin");
  await c.env.SESSIONS.delete(stateKey); // single use

  const tokenRes = await fetch(`https://login.microsoftonline.com/${c.env.TENANT_ID}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: c.env.CLIENT_ID,
      client_secret: c.env.CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: `${BASE_URL}/auth/callback`,
    }),
  });
  if (!tokenRes.ok) {
    console.error("SSPR token exchange failed:", tokenRes.status);
    return c.redirect("/?error=signin");
  }
  const tok = await tokenRes.json().catch(() => null);
  if (!tok?.access_token) return c.redirect("/?error=signin");

  const me = await graphMe(tok.access_token).catch(() => null);
  if (!me || me.accountEnabled === false) return c.redirect("/?error=signin");

  await startSession(c, {
    msAuthed: true,
    verified: false,
    name: me.displayName || "",
    upn: me.userPrincipalName || "",
    email: me.mail || me.userPrincipalName || "",
    access_token: tok.access_token,
    vc_state: null,
    createdAt: Date.now(),
  });
  return c.redirect("/");
});

// ============================================================
// VERIFIED ID (step 2) - background endpoints used by the one page
// ============================================================
// Polled by the page while the user approves in Authenticator.
app.get("/verify/status", async (c) => {
  const { sid, data } = await getSession(c);
  if (!data?.msAuthed || !data.vc_state) return c.json({ error: "expired" }, 410);

  const rec = safeJson(await c.env.SESSIONS.get(`vclogin:${data.vc_state}`));
  if (!rec || rec.sid !== sid) return c.json({ error: "expired" }, 410);
  return c.json({ status: rec.status || "pending" });
});

// Called by Verified ID with the presentation result.
app.post("/verify/callback", async (c) => {
  if (!c.env.VC_CALLBACK_KEY || c.req.header("api-key") !== c.env.VC_CALLBACK_KEY) {
    return c.json({ error: "unauthorized" }, 401);
  }
  const payload = await c.req.json().catch(() => null);
  const state = payload?.state;
  if (typeof state !== "string" || !/^[0-9a-f-]{36}$/i.test(state)) {
    return c.json({ error: "invalid_payload" }, 400);
  }

  const key = `vclogin:${state}`;
  const rec = safeJson(await c.env.SESSIONS.get(key));
  if (!rec) return c.json({ ok: true });

  let status = payload.requestStatus || "unknown";
  let email = null;
  let errorMessage = null;

  if (status === "presentation_verified") {
    const identity = getVerifiedIdentity(c.env, payload.verifiedCredentialsData);
    if (identity) {
      email = identity.email;
    } else {
      status = "presentation_error";
      errorMessage = "Credential not accepted";
    }
  }

  await c.env.SESSIONS.put(
    key,
    JSON.stringify({ ...rec, status, email, errorMessage, updatedAt: Date.now() }),
    { expirationTtl: 600 }
  );
  return c.json({ ok: true });
});

// Confirms the verified credential belongs to the same person who signed in with Microsoft.
app.get("/verify/complete", async (c) => {
  const { sid, data } = await getSession(c);
  if (!data?.msAuthed || !data.vc_state) return c.redirect("/?error=expired");

  const key = `vclogin:${data.vc_state}`;
  const rec = safeJson(await c.env.SESSIONS.get(key));
  await c.env.SESSIONS.delete(key).catch(() => {}); // single use

  if (!rec || rec.sid !== sid || rec.status !== "presentation_verified") {
    return c.redirect("/?error=verify");
  }

  const expected = [data.email, data.upn].filter(Boolean).map((v) => String(v).toLowerCase());
  if (!rec.email || !expected.includes(String(rec.email).toLowerCase())) {
    data.vc_state = null;
    await saveSession(c, sid, data);
    return c.redirect("/?error=identity");
  }

  data.verified = true;
  data.vc_state = null;
  data.verifiedAt = Date.now();
  await saveSession(c, sid, data);
  return c.redirect("/");
});

export default app;
