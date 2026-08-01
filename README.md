<div align="center">
  <h1>🚀 ISP-Register</h1>
  <p><b>The Ultimate, Database-Free ISPConfig Registration Portal</b></p>
  <p>
    <i>Developed by Andy Goldau | © 2026 PanelLayer (Subdomain LTD) & GoMaKe UG</i>
  </p>
  <p>
    📦 <b>Product Page:</b> <a href="https://isp-register.panellayer.com/">ISP-Register</a> &nbsp;|&nbsp;
    🧪 <b>Live Demo:</b> <a href="https://demo.isp-register.panellayer.com/">Demo</a> &nbsp;|&nbsp;
    🌐 <b>Project:</b> <a href="https://panellayer.com/">PanelLayer</a>
  </p>
</div>

---

**ISP-Register** is an incredibly robust, secure, and fully-featured self-service registration portal built specifically for **ISPConfig**. Designed from the ground up for maximum security, GDPR compliance, and styled 1:1 after the official ISPConfig 3 control panel interface, it requires **zero database setup** (100% flat-file logic) and handles client creation flawlessly through the native ISPConfig Remote API (JSON-RPC over cURL – no `php-soap` extension required).

> **DISCLAIMER:** This software is provided "as is" without any warranty of any kind. ISP-Register is an independent software solution and is not affiliated with, endorsed by, or sponsored by ISPConfig or its developers.

---

## ✨ Enterprise-Grade Features

### 🛡️ Unrivaled Security & Privacy
- **k-Anonymity Password Checks:** Integrates the *Have I Been Pwned* API directly in the client's browser using the Web Crypto API. Only the first 5 characters of a SHA-1 hash are transmitted—your plaintext password never leaves your browser.
- **Advanced Rate-Limiting (Token Bucket):** Fully protects the ISPConfig API against brute-force and DDoS spam attacks using a highly efficient, session-independent Token Bucket algorithm based on cryptographically hashed IPs.
- **No Database Required:** Works strictly with local flat files (JSON/PHP). All sensitive log files (`audit.log.php`, `used_codes.php`) are completely locked down and unreadable from the web, regardless of whether your webserver is Apache, LiteSpeed, or NGINX.
- **Strict Content Security Policy (CSP):** Ships with hardened HTTP response headers (CSP, HSTS, X-Frame-Options) out of the box, mitigating XSS and iframe-injection attacks.

### 🌐 Internationalization & Authentic UX
- **22 Supported Languages:** Comes fully translated into 22 languages (English, German, Bulgarian, Brazilian Portuguese, Croatian, Czech, Dutch, Finnish, French, Greek, Hungarian, Indonesian, Italian, Japanese, Polish, Portuguese, Romanian, Russian, Spanish, Swedish, Slovak, and Turkish).
- **Official ISPConfig 3 Theme:** Styled pixel-perfect after the clean, iconic ISPConfig 3 login panel with light gray background, official monitor SVG logo, and branded UI controls.
- **Live Password Checklist:** A real-time, side-by-side interactive UI element that instantly visually validates password complexity requirements.
- **Fail-open DNS MX Checks:** Automatically verifies the existence of mail servers (MX records) for the email domains entered during registration to prevent bot signups, featuring built-in caching.

### 🤖 Ultimate Anti-Bot Protection
Forget spam. We support natively integrated setups for:
- **hCaptcha**
- **reCAPTCHA (Google)**
- **Cloudflare Turnstile**
- **Altcha** (Proof-of-Work, 100% GDPR compliant)
- **MTCaptcha**

### 🎟️ Exclusive Access Modes
- **Invite-Only Mode:** Optionally lock your registration portal so only users with pre-generated, single-use, or multi-use invitation codes can join your platform.

---

## 🔌 ISPConfig API Integration

ISP-Register connects to ISPConfig via its **JSON-RPC Remote API** (`/remote/json.php`) using a dedicated Remote API user. No `php-soap` extension is needed – all calls are made via standard PHP cURL.

**Authentication flow for each registration:**
1. `POST /remote/json.php?login` → obtains a `session_id`
2. `POST /remote/json.php?client_add` → creates the client account
3. `POST /remote/json.php?logout` → cleans up the session

The new client's **ISPConfig login URL** is your panel address at port 8080 (e.g. `https://your-server.com:8080`). All user types (Admin, Reseller, Client) log in through the same interface; ISPConfig restricts features based on the account type automatically.

---

## 🚀 Installation & Setup

### 1. Create a Remote API User in ISPConfig
1. Log into your ISPConfig panel.
2. Navigate to **System → User Management → Remote Users**.
3. Click **Add new user**.
4. Set a username and a strong password.
5. Under **Functions**, enable at minimum:
   - **Client functions** (`client_add`, `client_get`, etc.)
   - **Client delete functions** (`client_delete_everything` - required if `DEMO_MODE` is enabled)
6. Optionally restrict the allowed IP to your webserver's IP for extra security.

### 2. Upload & Configure
1. **Upload & Extract:** Upload the contents to any PHP 8.x web directory.
2. **Configure:** Copy `config-blank.php` to `config.php` (if not present) and enter your:
   - ISPConfig Host & Port (`ISP_HOST`, `ISP_PORT` – default: 8080)
   - Remote API credentials (`ISP_REMOTE_USER`, `ISP_REMOTE_PASS`)
   - Reseller ID (`ISP_RESELLER_ID` – use `0` for admin-owned clients)
   - Desired CAPTCHA provider keys
   - Security toggles (HIBP, Invite-Mode, Audit Logging)
3. **Generate a Salt:** Replace the default `LOG_IP_SALT` in `config.php` with a random 32-character string to ensure IP pseudonymization in your audit logs.
4. **Done:** The system automatically creates and protects the necessary `data/` and `logs/` folders upon the first registration.

### 3. Demo Mode (optional)
If you enable `DEMO_MODE`, expired accounts are deleted automatically via `cron_cleanup.php` using `client_delete_everything`. The script stores the `client_id` (returned by ISPConfig after creation) in `data/demo_accounts.json` and uses it for deletion.

Add to crontab:
```bash
*/30 * * * * php /path/to/public_html/cron_cleanup.php >> /dev/null 2>&1
```

---

## 📄 License & Attribution

This project is licensed under the **MIT License**.

> **Developer:** [Andy Goldau](https://andy-goldau.de/) <br>
> **Copyright:** © 2026 ISP-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.  
> **Product Page:** [https://isp-register.panellayer.com/](https://isp-register.panellayer.com/)  
> **Live Demo:** [https://demo.isp-register.panellayer.com/](https://demo.isp-register.panellayer.com/)  
> **Project:** [https://panellayer.com/](https://panellayer.com/)

The above copyright notice, the developer attribution, and the permission notice must be included in all copies or substantial portions of the Software.
