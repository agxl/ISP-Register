<?php

/**
 * Developer: Andy Goldau
 * © 2026 ISP-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 * 
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * ISP-Register is an independent software solution and is not affiliated with, 
 * endorsed by, or sponsored by ISPConfig or its developers.
 */

/**
 * ISPConfig Registration Script – Configuration
 * --------------------------------------------------
 * Adjust these values to match your ISPConfig server.
 */

// ── ISPConfig Server ──────────────────────────────────────────────────────────
define('ISP_HOST', 'https://your-server.example.com'); // e.g. https://cp.example.com
define('ISP_PORT', 8080);                               // Integer: default ISPConfig port

// ── SSL Certificate Verification ─────────────────────────────────────────────
// Set to true in production (recommended).
// Set to false ONLY if your ISPConfig server uses a self-signed certificate.
define('ISP_SSL_VERIFY', true);

// ── Remote API User Credentials ──────────────────────────────────────────────
// SECURITY BEST PRACTICE: Create a dedicated Remote API user in ISPConfig under
// System → User Management → Remote Users.
// Grant ONLY the "client" permission group (client_add, client_get, etc.).
// Do NOT use your primary admin account.
//
// IMPORTANT: Even with automated registration, you must implement a manual
// vetting or auditing process for new customers to prevent spam, fraud,
// or abuse of your hosting infrastructure.
define('ISP_REMOTE_USER', 'remote_user');
define('ISP_REMOTE_PASS', 'your-remote-api-password');

// ── Reseller ID for New Clients ───────────────────────────────────────────────
// The reseller ID the new client will be assigned to.
// Use 0 if the client should belong directly to the admin (no reseller).
define('ISP_RESELLER_ID', 0);

// ── API Request Timeout ───────────────────────────────────────────────────────
// Maximum number of seconds to wait for an ISPConfig API response.
define('ISP_TIMEOUT', 90);

// ── Rate Limiting & Proxy Configuration ──────────────────────────────────────
// Set to true ONLY if your server is behind a trusted reverse proxy or Cloudflare.
// If set to false, REMOTE_ADDR will be used to prevent IP rate limit spoofing.
define('TRUST_PROXY_HEADERS', false);

define('RATE_LIMIT_MAX', 5);   // Maximum registrations per window
define('RATE_LIMIT_WINDOW', 300);  // Time window in seconds (5 minutes)

// ── Password Policy ─────────────────────────────────────────────────────────
// Minimum password length for new accounts (ISPConfig recommends at least 8).
define('PASSWD_MIN_LENGTH', 8);

// Require complex passwords (at least one uppercase letter, one lowercase letter, and one number).
define('PASSWD_REQUIRE_COMPLEXITY', true);

// Show a live password requirements checklist below the password field.
// Checklist items are driven by PASSWD_MIN_LENGTH and PASSWD_REQUIRE_COMPLEXITY above.
define('PASSWD_SHOW_CHECKLIST', true);

// ── Site Title & Branding ───────────────────────────────────────────────────
define('SITE_TITLE', 'ISPConfig – Registration');
define('PANEL_URL', ISP_HOST . ':' . ISP_PORT . '/');

// ── Card Heading & Subheading ────────────────────────────────────────────────
// The large heading and the small uppercase subtitle shown on the registration card.
define('CARD_HEADING', 'ISPConfig');
define('CARD_SUBHEADING', 'web control panel');

// ── Cookie Consent Banner ────────────────────────────────────────────────────
// Set to true to display a GDPR-compliant cookie consent banner.
// Users must accept cookies before the page stores any localStorage data.
define('COOKIE_BANNER_ENABLED', true);
// Text shown inside the cookie banner.
define('COOKIE_BANNER_TEXT', 'We use essential cookies for security (CSRF, session). By continuing, you agree to our cookie usage.');
// Label for the accept button.
define('COOKIE_BANNER_BTN', 'Accept & Continue');

// ── Accessibility Widget ─────────────────────────────────────────────────────
// Set to true to show a floating accessibility toolbar (font-size, contrast, grayscale).
define('ACCESSIBILITY_WIDGET_ENABLED', true);

// ── CAPTCHA Configuration ────────────────────────────────────────────────────
// Choose ONE provider: 'none' | 'hcaptcha' | 'recaptcha' | 'altcha' | 'turnstile' | 'mtcaptcha'
define('CAPTCHA_PROVIDER', 'hcaptcha');

// hCaptcha – https://dashboard.hcaptcha.com
// Register at hcaptcha.com to obtain your site key and secret key.
define('HCAPTCHA_SITE_KEY', 'your-hcaptcha-site-key');
define('HCAPTCHA_SECRET_KEY', 'your-hcaptcha-secret-key');

// Google reCAPTCHA v2 – https://www.google.com/recaptcha/admin
// Register your domain to obtain site key and secret key.
define('RECAPTCHA_SITE_KEY', 'your-recaptcha-site-key');
define('RECAPTCHA_SECRET_KEY', 'your-recaptcha-secret-key');

// ALTCHA – self-hosted, no external account required.
// !! REQUIRED: Replace with a strong random secret before deployment !!
// Generate one with: openssl rand -hex 32
define('ALTCHA_HMAC_KEY', 'CHANGE_THIS_TO_A_STRONG_RANDOM_SECRET');

// Cloudflare Turnstile – https://dash.cloudflare.com/?to=/:account/turnstile
// Privacy-friendly, often invisible. Free tier available. No Cloudflare proxying required.
// Frontend field name submitted: 'cf-turnstile-response'
// Backend validation endpoint: https://challenges.cloudflare.com/turnstile/v0/siteverify
// Test keys (always pass): sitekey=1x00000000000000000000AA, secret=1x0000000000000000000000000000000AA
define('TURNSTILE_SITE_KEY', 'your-turnstile-site-key');
define('TURNSTILE_SECRET_KEY', 'your-turnstile-secret-key');

// MTCaptcha – https://admin.mtcaptcha.com
// GDPR-compliant, free tier available, supports 70+ languages natively.
// Frontend field name submitted: 'mtcaptcha-verifiedtoken'
// Backend validation endpoint: GET https://service.mtcaptcha.com/mtcv1/api/checktoken
define('MTCAPTCHA_SITE_KEY', 'your-mtcaptcha-sitekey');
define('MTCAPTCHA_PRIVATE_KEY', 'your-mtcaptcha-privatekey');

// ── Legal / Compliance (DSGVO / GDPR) ─────────────────────────────────────
// Links to Terms of Service and Privacy Policy. If empty, the links are hidden.
define('TOS_URL', 'https://example.com/agb');
define('PRIVACY_URL', 'https://example.com/datenschutz');

// ── Font Provider (DSGVO / GDPR Compliance) ─────────────────────────────────
// Choose font provider: 'bunny' (Bunny Fonts - DSGVO compliant, default) | 'google' (Google Fonts) | 'none' (System Fonts)
define('FONT_PROVIDER', 'bunny');


// ── Support / Contact ────────────────────────────────────────────────────────
// Add an email address or a helpdesk URL to be displayed below the form.
// If both are empty, the support section is hidden.
define('SUPPORT_EMAIL', 'support@example.com');
define('SUPPORT_URL', ''); // e.g. https://helpdesk.example.com

// Email address for password reset requests (can be the same as SUPPORT_EMAIL).
// The user will get a pre-filled mailto: link with subject "Password Reset Request".
define('SUPPORT_RESET_EMAIL', 'support@example.com');

// ── Abuse Protection (Disposable Email Blocker) ───────────────────────────
// Block these domains from registering accounts to prevent spam.
define('BLOCKED_EMAIL_DOMAINS', [
    '10minutemail.com',
    'trashmail.de',
    'trashmail.com',
    'mailinator.com',
    'yopmail.com',
    'guerrillamail.com',
    'temp-mail.org',
    'tempmail.com',
    'sharklasers.com',
    'dispostable.com',
    'maildrop.cc'
]);

// ── Admin Notifications (Email & Webhook) ─────────────────────────────────
// Set to a valid email address to receive notifications, or leave empty to disable.
define('ADMIN_EMAIL', '');

// Set to a Discord/Slack webhook URL to receive notifications on successful registrations.
define('WEBHOOK_ENABLED', false); // true to enable
define('WEBHOOK_URL', 'https://discord.com/api/webhooks/your-webhook-id/your-webhook-token');

// ── Maintenance Mode ──────────────────────────────────────────────────────
// Set to true to disable new registrations and show a maintenance message.
define('MAINTENANCE_MODE', false);

// ── Reserved Names & Domains ──────────────────────────────────────────────
// Prevent registration of system-critical or administrative usernames.
define('RESERVED_USERNAMES', [
    'admin',
    'administrator',
    'root',
    'support',
    'billing',
    'webmaster',
    'hostmaster',
    'postmaster',
    'sysadmin',
    'info',
    'test'
]);

// Prevent registration of specific domains (e.g. your own hosting domains).
define('RESERVED_DOMAINS', [
    'example.com',
    'yourhosting.com'
]);

// If set to true, subdomains of reserved domains (e.g. sub.example.com) will also be blocked.
// If set to false, only exact domain matches are blocked, allowing users to register subdomains.
define('BLOCK_RESERVED_SUBDOMAINS', false);

// ── DNS MX Record Check ────────────────────────────────────────────────────
// Verify that the email domain has valid MX records before accepting registration.
// If DNS is unreachable, the check is skipped (fail-open) to avoid false positives.
define('ENABLE_MX_CHECK', true);

// ── HaveIBeenPwned Password Check ─────────────────────────────────────────
// Checks the password against the HIBP Pwned Passwords API using k-anonymity.
// The full password NEVER leaves the browser – only a 5-char SHA-1 prefix is sent.
// No API key required. The Pwned Passwords API is free and CORS-enabled.
define('ENABLE_HIBP_CHECK', true);
// If true, a breached password causes a hard registration error (blocked).
// If false, the user only sees a warning but can still proceed.
define('HIBP_BLOCK_ON_BREACH', false);

// ── Audit Log ──────────────────────────────────────────────────────────────────
// Log all registration attempts (success and failure) to a JSON-Lines file.
// IPs are pseudonymized using a salted hash (GDPR-compliant).
define('AUDIT_LOG_ENABLED', true);
define('AUDIT_LOG_PATH', __DIR__ . '/logs/audit.log.php');
define('AUDIT_LOG_MAX_SIZE', 10 * 1024 * 1024); // 10 MB – rotate when exceeded
// !! REQUIRED: Replace with a random string to pseudonymize IPs for GDPR compliance !!
// Generate one with: openssl rand -hex 16
define('LOG_IP_SALT', 'CHANGE_TO_RANDOM_SALT_FOR_GDPR');

// ── Invite Codes (Invite-Only Mode) ──────────────────────────────────────────
// If true, users must enter a valid invite code to register.
define('INVITE_ONLY_MODE', false);
// If true, each code can only be used once. Used codes are stored in INVITE_CODES_FILE.
define('INVITE_SINGLE_USE', true);
// List of valid invite codes. Add or remove codes here.
define('INVITE_CODES', [
    'WELCOME-2026',
    'BETA-ACCESS',
    'VIP-HOSTING',
]);
// Path to the flat file storing used invite codes. Must NOT be web-accessible.
define('INVITE_CODES_FILE', __DIR__ . '/data/used_codes.php');

// ── Demo Mode ─────────────────────────────────────────────────────────────────
// When enabled, all successfully created accounts are tracked in a JSON file
// and automatically deleted via a cronjob after DEMO_LIFETIME_HOURS hours.
//
// Setup (run this cronjob on your ISPConfig server):
//   crontab -e
//   Add the following line (runs every 30 minutes):
//   */30 * * * * php /path/to/public_html/cron_cleanup.php >> /dev/null 2>&1
//
// Set to true to enable demo mode, false to disable.
define('DEMO_MODE', false);

// How long (in hours) to keep demo accounts before automatic deletion.
// Minimum: 1 | Recommended for demos: 2–24
define('DEMO_LIFETIME_HOURS', 2);

// Path to the JSON file that tracks demo accounts.
// This file is automatically created on first use. Keep it outside the webroot
// or ensure it is protected by the data/.htaccess rule.
define('DEMO_ACCOUNTS_FILE', __DIR__ . '/data/demo_accounts.json');
