<?php

/**
 * Developer: Andy Goldau
 * © 2026 ISP-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 * 
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * ISP-Register is an independent software solution and is not affiliated with, 
 * endorsed by, or sponsored by ISPConfig or its developers.
 */

// Suppress PHP error output to prevent information disclosure
error_reporting(0);
ini_set('display_errors', '0');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
  || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
  || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

session_start([
  'cookie_httponly' => true,
  'cookie_samesite' => 'Lax',
  'cookie_secure'   => $isHttps,
]);
require_once __DIR__ . '/config.php';

// ── Security Headers ───────────────────────────────────────────────────────
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header(
  "Content-Security-Policy: default-src 'self'; "
  . "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net "
  . "https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com https://www.google.com https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.bunny.net; "
  . "font-src 'self' https://fonts.gstatic.com https://fonts.bunny.net; "
  . "connect-src 'self' https://api.hcaptcha.com https://*.hcaptcha.com https://challenges.cloudflare.com https://www.google.com https://service.mtcaptcha.com https://service2.mtcaptcha.com https://api.pwnedpasswords.com; "
  . "img-src 'self' data: https://*.hcaptcha.com https://www.google.com https://www.gstatic.com https://service.mtcaptcha.com https://service2.mtcaptcha.com;"
);
if ($isHttps) {
  header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
}


// ── CSRF Token ─────────────────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

// ── Rate Limiting (Token Bucket) ──────────────────────────────────────────
if (defined('TRUST_PROXY_HEADERS') && TRUST_PROXY_HEADERS) {
  $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
} else {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
$ip = explode(',', trim($ip))[0];

$rateLimitDir = __DIR__ . '/data/limits';
if (!is_dir($rateLimitDir)) @mkdir($rateLimitDir, 0750, true);

$ipHash = hash('sha256', (defined('LOG_IP_SALT') ? LOG_IP_SALT : 'fallback') . $ip);
$limitFile = $rateLimitDir . '/limit_' . $ipHash . '.php';

$capacity = RATE_LIMIT_MAX;
$refillRate = $capacity / RATE_LIMIT_WINDOW;
$tokens = $capacity;
$lastUpdate = time();

$rateLimited = false;
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

$fp = @fopen($limitFile, 'c+');
if ($fp) {
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    if (strlen($raw) > 15) {
      $data = json_decode(substr($raw, 15), true);
      if (is_array($data)) {
        $tokens = $data['tokens'] ?? $capacity;
        $lastUpdate = $data['last_update'] ?? time();
      }
    }
    
    $now = time();
    $elapsed = $now - $lastUpdate;
    $tokens += $elapsed * $refillRate;
    if ($tokens > $capacity) $tokens = $capacity;
    
    if ($isPost) {
      if ($tokens >= 1) {
        $tokens -= 1;
        $rateLimited = false;
      } else {
        $rateLimited = true;
      }
    } else {
      $rateLimited = ($tokens < 1);
    }
    
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, "<?php exit; ?>\n" . json_encode([
      'tokens' => $tokens,
      'last_update' => $now
    ]));
    
    flock($fp, LOCK_UN);
  }
  fclose($fp);
}

// ── ISPConfig JSON-RPC helper ─────────────────────────────────────────────
/**
 * Sends a JSON-RPC request to the ISPConfig remote/json.php endpoint.
 * Returns the decoded JSON response array or an empty array on failure.
 */
function ispJsonRpc(string $method, array $params, int $timeout = 30): array
{
  $baseUrl = ISP_HOST . ':' . ISP_PORT . '/remote/json.php?' . $method;
  $payload = json_encode($params);

  $ch = curl_init($baseUrl);
  curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $payload,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => ISP_SSL_VERIFY,
    CURLOPT_SSL_VERIFYHOST => ISP_SSL_VERIFY ? 2 : 0,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT        => $timeout,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
  ]);
  $response = curl_exec($ch);
  $errno    = curl_errno($ch);
  curl_close($ch);

  if ($errno || !$response) {
    return [];
  }
  return json_decode((string) $response, true) ?? [];
}

// ── ISPConfig API Function ────────────────────────────────────────────────
/**
 * Creates a new ISPConfig client via the remote JSON-RPC API.
 * Flow: login → client_add → logout.
 * Returns ['success' => bool, 'message' => string, 'client_id' => int|null]
 */
function ispCreateClient(array $data): array
{
  $timeout = defined('ISP_TIMEOUT') ? ISP_TIMEOUT : 90;

  // Step 1 – Authenticate and obtain session_id
  $loginResp = ispJsonRpc('login', [
    'username'     => ISP_REMOTE_USER,
    'password'     => ISP_REMOTE_PASS,
    'client_login' => false,
  ], 15);

  if (empty($loginResp)) {
    return ['success' => false, 'message' => 'Connection to ISPConfig server failed. Please check ISP_HOST and ISP_PORT.', 'client_id' => null];
  }

  if (!empty($loginResp['code']) && $loginResp['code'] === 'login_failed') {
    return ['success' => false, 'message' => 'Authentication failed. Please check ISP_REMOTE_USER and ISP_REMOTE_PASS.', 'client_id' => null];
  }

  $sessionId = $loginResp['response'] ?? null;
  if (!$sessionId) {
    $msg = !empty($loginResp['message']) ? htmlspecialchars($loginResp['message']) : 'Login to ISPConfig API failed (no session_id returned).';
    return ['success' => false, 'message' => $msg, 'client_id' => null];
  }

  // Step 2 – Create client account
  $clientParams = [
    'contact_name' => $data['username'],
    'username'     => $data['username'],
    'password'     => $data['passwd'],
    'email'        => $data['email'],
    'company_name' => $data['domain'],  // store domain as company_name for reference
    'active'       => 'y',
  ];

  $createResp = ispJsonRpc('client_add', [
    'session_id'      => $sessionId,
    'reseller_id'     => defined('ISP_RESELLER_ID') ? (int) ISP_RESELLER_ID : 0,
    'params'          => $clientParams,
  ], $timeout);

  // Step 3 – Logout (always, regardless of result)
  ispJsonRpc('logout', ['session_id' => $sessionId], 10);

  if (empty($createResp)) {
    return ['success' => false, 'message' => 'No response from ISPConfig API after client_add call.', 'client_id' => null];
  }

  // ISPConfig JSON API returns the new client_id (integer) on success
  $code     = $createResp['code']     ?? '';
  $message  = $createResp['message']  ?? '';
  $response = $createResp['response'] ?? null;

  if ($code === 'ok' && is_numeric($response) && (int) $response > 0) {
    return ['success' => true, 'message' => 'Account successfully created!', 'client_id' => (int) $response];
  }

  // Error response
  $errMsg = !empty($message) ? htmlspecialchars($message) : 'Unknown error from ISPConfig API.';
  return ['success' => false, 'message' => $errMsg, 'client_id' => null];
}

// ── Audit Log ──────────────────────────────────────────────────────────────
/**
 * Writes a GDPR-compliant, JSON-Lines audit entry to the log file.
 * IPs are pseudonymized via a salted SHA-256 hash (not reversible without the salt).
 * Email addresses are masked to protect PII (e.g. j***@gmail.com).
 * The log file is rotated when it exceeds AUDIT_LOG_MAX_SIZE bytes.
 */
function auditLog(string $username, string $email, string $domain, string $result, string $reason): void
{
  if (!defined('AUDIT_LOG_ENABLED') || !AUDIT_LOG_ENABLED) return;

  $logPath = AUDIT_LOG_PATH;
  $logDir  = dirname($logPath);
  if (!is_dir($logDir)) @mkdir($logDir, 0750, true);

  // Rotate if over size limit
  if (file_exists($logPath) && filesize($logPath) > AUDIT_LOG_MAX_SIZE) {
    @rename($logPath, $logPath . '.' . date('Ymd-His'));
  }

  // Pseudonymize IP (GDPR: no plaintext personal data)
  $rawIp  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  $anonIp = substr(hash('sha256', $rawIp . LOG_IP_SALT), 0, 16);

  // Mask email (keep first char + domain for debugging)
  $maskedEmail = '';
  if ($email && strpos($email, '@') !== false) {
    [$local, $dom] = explode('@', $email, 2);
    $maskedEmail   = substr($local, 0, 1) . '***@' . $dom;
  }

  $entry = json_encode([
    't'      => date('c'),
    'ip'     => $anonIp,
    'user'   => $username,
    'domain' => $domain,
    'email'  => $maskedEmail,
    'result' => $result,
    'reason' => $reason ?: null,
  ], JSON_UNESCAPED_UNICODE);

  $fp = @fopen($logPath, 'a');
  if ($fp) {
    flock($fp, LOCK_EX);
    if (filesize($logPath) === 0) {
      fwrite($fp, "<?php exit; ?>\n");
    }
    fwrite($fp, $entry . "\n");
    flock($fp, LOCK_UN);
    fclose($fp);
  }
}

// ── DNS MX Check ───────────────────────────────────────────────────────────
/**
 * Checks if a domain has valid MX records.
 * Results are cached in the session for 60s to prevent DNS flooding on retries.
 * Fail-open: returns true if DNS resolution itself fails.
 */
function checkEmailMx(string $domain): bool
{
  if (!defined('ENABLE_MX_CHECK') || !ENABLE_MX_CHECK) return true;
  if (!$domain) return false;

  $cacheKey = 'mx_' . md5($domain);
  if (isset($_SESSION[$cacheKey]) && (time() - $_SESSION[$cacheKey]['ts']) < 60) {
    return $_SESSION[$cacheKey]['result'];
  }

  // checkdnsrr returns false on both "no MX" and "resolution failure"
  // Use dns_get_record for more control; fall back to true on error (fail-open)
  set_error_handler(function() {}, E_WARNING);
  $records = dns_get_record($domain, DNS_MX | DNS_A);
  restore_error_handler();

  // Fail-open: if dns_get_record returns false (DNS unavailable), allow registration
  if ($records === false) {
    $_SESSION[$cacheKey] = ['result' => true, 'ts' => time()];
    return true;
  }

  $hasMx = !empty($records);
  $_SESSION[$cacheKey] = ['result' => $hasMx, 'ts' => time()];
  return $hasMx;
}

// ── Invite Code Validation ─────────────────────────────────────────────────
/**
 * Validates an invite code and marks it as used if INVITE_SINGLE_USE is true.
 * Uses exclusive file locking to prevent race conditions.
 */
function validateInviteCode(string $code): bool
{
  if (!defined('INVITE_ONLY_MODE') || !INVITE_ONLY_MODE) return true;

  $code = strtoupper(preg_replace('/[^A-Z0-9\-]/', '', strtoupper(trim($code))));
  if (!$code) return false;

  // Check against configured valid codes (timing-safe loop)
  $isValid = false;
  foreach (INVITE_CODES as $validCode) {
    if (hash_equals(strtoupper(trim($validCode)), $code)) {
      $isValid = true;
      break;
    }
  }
  if (!$isValid) return false;

  if (!defined('INVITE_SINGLE_USE') || !INVITE_SINGLE_USE) return true;

  // Check and mark as used via flat file with exclusive lock
  $file = INVITE_CODES_FILE;
  $dir  = dirname($file);
  if (!is_dir($dir)) @mkdir($dir, 0750, true);
  if (!file_exists($file)) file_put_contents($file, "<?php exit; ?>\n" . json_encode(['used' => []]));

  $fp = @fopen($file, 'r+');
  if (!$fp) return false; // Cannot acquire file handle → deny

  $result = false;
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    $jsonStr = substr($raw, 15) ?: '{}';
    $data = json_decode($jsonStr, true) ?? ['used' => []];
    if (!in_array($code, (array)($data['used'] ?? []), true)) {
      $data['used'][] = $code;
      rewind($fp);
      ftruncate($fp, 0);
      fwrite($fp, "<?php exit; ?>\n" . json_encode($data, JSON_PRETTY_PRINT));
      $result = true;
    }
    flock($fp, LOCK_UN);
  }
  fclose($fp);
  return $result;
}



/**
 * Sends a POST request to a CAPTCHA verification API and returns decoded JSON.
 */
function captchaCurl(string $url, array $data): array
{
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => http_build_query($data),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_TIMEOUT => 10,
  ]);
  $res = curl_exec($ch);
  curl_close($ch);
  return json_decode((string) $res, true) ?? [];
}

/**
 * Verifies an ALTCHA proof-of-work payload without any external API call.
 * Steps: decode base64-JSON → check algorithm → verify PoW hash → verify HMAC signature → check expiry.
 */
function verifyAltchaPayload(string $payload): bool
{
  if (!$payload)
    return false;
  $data = json_decode(base64_decode($payload), true);
  if (!is_array($data))
    return false;

  $alg = $data['algorithm'] ?? '';
  $challenge = $data['challenge'] ?? '';
  $salt = $data['salt'] ?? '';
  $number = (string) ($data['number'] ?? '');
  $signature = $data['signature'] ?? '';

  // Only SHA-256 is supported
  if ($alg !== 'SHA-256')
    return false;

  // Check expiry embedded in salt params (e.g. "abc123?expires=1234567890")
  $query = parse_url($salt, PHP_URL_QUERY) ?? '';
  parse_str($query, $saltParams);
  if (isset($saltParams['expires']) && time() > (int) $saltParams['expires'])
    return false;

  // Verify Proof-of-Work: hash(salt + number) must equal challenge
  if (hash('sha256', $salt . $number) !== $challenge)
    return false;

  // Verify HMAC signature: prevents crafted challenges
  $expected = hash_hmac('sha256', $challenge, ALTCHA_HMAC_KEY);
  return hash_equals($expected, $signature);
}

/**
 * Dispatches to the configured CAPTCHA provider and returns true on success.
 */
function verifyCaptcha(): bool
{
  $provider = CAPTCHA_PROVIDER;
  if ($provider === 'none')
    return true;

  if ($provider === 'hcaptcha') {
    $token = $_POST['h-captcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://api.hcaptcha.com/siteverify', [
      'secret' => HCAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'recaptcha') {
    $token = $_POST['g-recaptcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://www.google.com/recaptcha/api/siteverify', [
      'secret' => RECAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'altcha') {
    return verifyAltchaPayload($_POST['altcha'] ?? '');
  }

  if ($provider === 'turnstile') {
    $token = $_POST['cf-turnstile-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
      'secret' => TURNSTILE_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'mtcaptcha') {
    $token = $_POST['mtcaptcha-verifiedtoken'] ?? '';
    if (!$token)
      return false;
    // MTCaptcha uses GET for verification
    $url = 'https://service.mtcaptcha.com/mtcv1/api/checktoken'
      . '?privatekey=' . urlencode(MTCAPTCHA_PRIVATE_KEY)
      . '&token=' . urlencode($token);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_SSL_VERIFYPEER => true,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_TIMEOUT => 10,
    ]);
    $res = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno || !$res)
      return false;
    $parsed = json_decode($res, true);
    return ($parsed['success'] ?? false) === true;
  }

  return false;
}

// ── Process Form ───────────────────────────────────────────────────────────
$result = null;
if ($rateLimited && $_SERVER['REQUEST_METHOD'] !== 'POST') {
  $result = ['success' => false, 'message' => 'Too many registration attempts. Please wait a few minutes before trying again.'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Honeypot check
  if (!empty($_POST['website_hp'])) {
    // Silently drop bot registration but pretend it succeeded
    $result = ['success' => true, 'message' => 'Account successfully created!'];
  } elseif (!hash_equals($csrf, $_POST['csrf_token'] ?? '')) {
    $result = ['success' => false, 'message' => 'Invalid security token. Please refresh the page.'];
  } elseif ($rateLimited) {
    $result = ['success' => false, 'message' => 'Too many registrations. Please wait a few minutes.'];
  } elseif (CAPTCHA_PROVIDER !== 'none' && !verifyCaptcha()) {
    $result = ['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.'];
  } else {
    $username = strtolower(trim($_POST['username'] ?? ''));
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $domain = trim($_POST['domain'] ?? '');
    $passwd = $_POST['passwd'] ?? '';
    $passwd2 = $_POST['passwd2'] ?? '';
    $emailDomain = $email ? substr(strrchr($email, "@"), 1) : '';

    // Reserved Names Check
    $isReservedDomain = false;
    if (!empty($domain)) {
      $lowerDomain = strtolower($domain);
      $blockSub = defined('BLOCK_RESERVED_SUBDOMAINS') && BLOCK_RESERVED_SUBDOMAINS;
      foreach (RESERVED_DOMAINS as $rd) {
        $lowerRd = strtolower($rd);
        if ($lowerDomain === $lowerRd) {
          $isReservedDomain = true;
          break;
        }
        if ($blockSub && str_ends_with($lowerDomain, '.' . $lowerRd)) {
          $isReservedDomain = true;
          break;
        }
      }
    }

    if (MAINTENANCE_MODE) {
      $result = ['success' => false, 'message' => 'Registrations are currently paused.'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'maintenance_mode');
    } elseif ((!empty(TOS_URL) || !empty(PRIVACY_URL)) && empty($_POST['tos_agree'])) {
      $result = ['success' => false, 'message' => 'You must agree to the Terms of Service and Privacy Policy.'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'tos_not_agreed');
    } elseif (INVITE_ONLY_MODE && !validateInviteCode($_POST['invite_code'] ?? '')) {
      $result = ['success' => false, 'message' => 'invite_invalid'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'invite_invalid');
    } elseif (!preg_match('/^[a-z0-9]{4,8}$/', $username)) {
      $result = ['success' => false, 'message' => 'Username must be 4-8 characters long (a-z, 0-9 only).'];
      auditLog($username, $email ?: '', $domain ?? '', 'fail', 'username_invalid');
    } elseif (in_array(strtolower($username), RESERVED_USERNAMES)) {
      $result = ['success' => false, 'message' => 'This username is reserved and cannot be registered.'];
      auditLog($username, $email ?: '', $domain ?? '', 'fail', 'username_reserved');
    } elseif (!$email) {
      $result = ['success' => false, 'message' => 'Please enter a valid email address.'];
      auditLog($username, '', $domain ?? '', 'fail', 'email_invalid');
    } elseif ($emailDomain && in_array(strtolower($emailDomain), BLOCKED_EMAIL_DOMAINS)) {
      $result = ['success' => false, 'message' => 'This email provider is not allowed. Please use a valid email address.'];
      auditLog($username, $email, $domain ?? '', 'fail', 'email_domain_blocked');
    } elseif ($emailDomain && !checkEmailMx($emailDomain)) {
      $result = ['success' => false, 'message' => 'email_mx_invalid'];
      auditLog($username, $email, $domain ?? '', 'fail', 'email_mx_no_records');
    } elseif (empty($domain) || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || strpos($domain, '.') === false) {
      $result = ['success' => false, 'message' => 'Please enter a valid domain (e.g. example.com).'];
      auditLog($username, $email, $domain ?? '', 'fail', 'domain_invalid');
    } elseif ($isReservedDomain) {
      $result = ['success' => false, 'message' => 'This domain is reserved and cannot be registered.'];
      auditLog($username, $email, $domain, 'fail', 'domain_reserved');
    } elseif (strlen($passwd) < PASSWD_MIN_LENGTH) {
      $result = ['success' => false, 'message' => 'Password must be at least ' . PASSWD_MIN_LENGTH . ' characters long.'];
      auditLog($username, $email, $domain, 'fail', 'password_too_short');
    } elseif (PASSWD_REQUIRE_COMPLEXITY && (!preg_match('/[A-Z]/', $passwd) || !preg_match('/[a-z]/', $passwd) || !preg_match('/[0-9]/', $passwd))) {
      $result = ['success' => false, 'message' => 'Password must contain at least one uppercase letter, one lowercase letter, and one number.'];
      auditLog($username, $email, $domain, 'fail', 'password_complexity');
    } elseif ($passwd !== $passwd2) {
      $result = ['success' => false, 'message' => 'Passwords do not match.'];
      auditLog($username, $email, $domain, 'fail', 'password_mismatch');
    } else {
      // Allow up to 120 seconds for slow ISPConfig server responses
      @set_time_limit(120);

      // Release PHP session lock so session file is not locked during long ISPConfig API request
      if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
      }

      $result = ispCreateClient([
        'username' => $username,
        'email' => $email,
        'domain' => $domain,
        'passwd' => $passwd,
        'passwd2' => $passwd2,
      ]);

      auditLog($username, $email, $domain, $result['success'] ? 'success' : 'fail', $result['success'] ? '' : 'isp_api_error');
      if ($result['success']) {
        if (WEBHOOK_ENABLED && !empty(WEBHOOK_URL)) {
          $payload = json_encode(['content' => "🔔 **New Registration**\nUser: `{$username}`\nDomain: `{$domain}`\nEmail: `{$email}`"]);
          $ch = curl_init(WEBHOOK_URL);
          curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
          curl_setopt($ch, CURLOPT_POST, 1);
          curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
          curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
          curl_setopt($ch, CURLOPT_TIMEOUT, 3);
          curl_exec($ch);
          curl_close($ch);
        }

        if (!empty(ADMIN_EMAIL)) {
          $subject = "New Registration: $username";
          $msg = "A new user has registered.\n\nUsername: $username\nDomain: $domain\nEmail: $email\nDate: " . date('Y-m-d H:i:s') . "\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
          $rawHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
          $host = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $rawHost) ?: 'localhost';
          $headers = "From: no-reply@" . $host . "\r\n" .
            "Reply-To: " . filter_var($email, FILTER_SANITIZE_EMAIL) . "\r\n" .
            "X-Mailer: ISP-Register";
          @mail(ADMIN_EMAIL, $subject, $msg, $headers);
        }

        // ── Demo Mode: Track account for scheduled deletion ─────────────────
        if (defined('DEMO_MODE') && DEMO_MODE) {
          $demoFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');
          $demoDir  = dirname($demoFile);
          if (!is_dir($demoDir)) { @mkdir($demoDir, 0750, true); }
          $accounts = [];
          if (is_file($demoFile)) {
            $raw = file_get_contents($demoFile);
            $accounts = json_decode($raw, true) ?: [];
          }
          // client_id is required by cron_cleanup.php to call client_delete_everything
          $accounts[$username] = [
            'client_id'   => $result['client_id'] ?? null,
            'domain'      => $domain,
            'email'       => ($email && strpos($email, '@') !== false)
                              ? (substr($email, 0, 1) . '***@' . substr(strrchr($email, '@'), 1))
                              : '',
            'created_at'  => time(),
            'delete_after'=> time() + (defined('DEMO_LIFETIME_HOURS') ? (int)DEMO_LIFETIME_HOURS : 2) * 3600,
          ];
          file_put_contents($demoFile, json_encode($accounts, JSON_PRETTY_PRINT), LOCK_EX);
        }
      }
    }
  }

  // Re-open session if closed to safely update CSRF token on success
  if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start([
      'cookie_httponly' => true,
      'cookie_samesite' => 'Lax',
      'cookie_secure'   => $isHttps,
    ]);
  }

  if ($result && $result['success']) {
    // Regenerate session ID to prevent session fixation attacks
    session_regenerate_id(true);
    // Regenerate CSRF token only on successful account creation
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $csrf = $_SESSION['csrf_token'];
  } else {
    // Keep existing CSRF token intact on form re-display / validation error
    $csrf = $_SESSION['csrf_token'] ?? $csrf;
  }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title><?= SITE_TITLE ?></title>
  <meta name="description" content="ISPConfig Account Registration" />
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet" />
  <meta name="googlebot" content="noindex, nofollow" />
  <link rel="icon" type="image/svg+xml"
    href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 42 42'%3E%3Crect width='42' height='42' rx='10' fill='%23cc0000'/%3E%3Cpath d='M8 21L16 13L24 21L16 29L8 21Z' fill='%23ffffff'/%3E%3Cpath d='M18 21L26 13L34 21L26 29L18 21Z' fill='%23ffffff' opacity='.6'/%3E%3C/svg%3E" />
  <?php
  $fontProvider = defined('FONT_PROVIDER') ? FONT_PROVIDER : 'bunny';
  if ($fontProvider === 'bunny'): ?>
    <link rel="preconnect" href="https://fonts.bunny.net" />
    <link href="https://fonts.bunny.net/css?family=inter:300,400,500,600&amp;display=swap" rel="stylesheet" />
  <?php elseif ($fontProvider === 'google'): ?>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&amp;display=swap" rel="stylesheet" />
  <?php endif; ?>
  <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"></script>
  <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
    <script>
      var mtcaptchaConfig = { "sitekey": "<?= htmlspecialchars(MTCAPTCHA_SITE_KEY) ?>" };
      (function () {
        var mt_service = document.createElement('script');
        mt_service.async = true;
        mt_service.src = 'https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service);
        var mt_service2 = document.createElement('script');
        mt_service2.async = true;
        mt_service2.src = 'https://service2.mtcaptcha.com/mtcv1/client/mtcaptcha2.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service2);
      })();
    </script>
  <?php endif; ?>
  <style>
    :root {
      --bg: #f2f4f7;
      --card: #ffffff;
      --card-b: #d0d5dd;
      --input-bg: #ffffff;
      --input-b: #c8cdd6;
      --input-bh: #999999;
      --text: #1a1f2e;
      --sub: #6b7280;
      --btn: #e9ecef;
      --btn-h: #a80000;
      --btn-text: #333333;
      --err-bg: rgba(204, 0, 0, .07);
      --err-b: rgba(204, 0, 0, .3);
      --err-text: #b91c1c;
      --ok-bg: rgba(22, 163, 74, .08);
      --ok-b: rgba(22, 163, 74, .3);
      --ok-text: #16a34a;
      --time: #9ca3af;
      --icon-btn: rgba(0, 0, 0, .06);
      --icon-bth: rgba(0, 0, 0, .12);
      --sb-track: rgba(0, 0, 0, .06);
      --sb-thumb: rgba(0, 0, 0, .2);
      --sb-thumb-h: rgba(0, 0, 0, .35);
    }

    /* ISPConfig has no separate dark mode – keeping a minimal dark variant for accessibility toggle */
    [data-theme="dark"] {
      --bg: #1a1f2e;
      --card: #242a38;
      --card-b: rgba(255,255,255,.08);
      --input-bg: #2d3548;
      --input-b: rgba(255,255,255,.12);
      --input-bh: #e05252;
      --text: #e8ecf4;
      --sub: #8a93a8;
      --btn: #cc0000;
      --btn-h: #a80000;
      --btn-text: #fff;
      --err-bg: rgba(204,0,0,.15);
      --err-b: rgba(204,0,0,.4);
      --err-text: #f87171;
      --ok-bg: rgba(22,163,74,.12);
      --ok-b: rgba(22,163,74,.4);
      --ok-text: #4ade80;
      --time: #5a6478;
      --icon-btn: rgba(255,255,255,.08);
      --icon-bth: rgba(255,255,255,.16);
      --sb-track: rgba(0,0,0,.2);
      --sb-thumb: rgba(255,255,255,.2);
      --sb-thumb-h: rgba(255,255,255,.35);
    }

    *,
    *::before,
    *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0
    }

    * {
      scrollbar-width: thin;
      scrollbar-color: var(--sb-thumb) var(--sb-track)
    }

    ::-webkit-scrollbar {
      width: 8px;
      height: 8px
    }

    ::-webkit-scrollbar-track {
      background: var(--sb-track);
      border-radius: 4px
    }

    ::-webkit-scrollbar-thumb {
      background: var(--sb-thumb);
      border-radius: 4px;
      transition: background .2s
    }

    ::-webkit-scrollbar-thumb:hover {
      background: var(--sb-thumb-h)
    }

    body {
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      transition: background .35s, color .35s;
      position: relative;
      overflow-x: hidden;
      overflow-y: auto;
    }

    /* Preloader */
    #preloader {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: var(--bg);
      z-index: 9999;
      display: grid;
      place-content: center;
      transition: opacity 0.5s ease, visibility 0.5s ease;
    }

    #preloader.hidden {
      opacity: 0;
      visibility: hidden;
    }

    #preloader-spinner {
      color: #cc0000;
      display: inline-block;
      position: relative;
      width: 80px;
      height: 80px;
    }

    #preloader-spinner div {
      box-sizing: border-box;
      display: block;
      position: absolute;
      width: 96px;
      height: 96px;
      margin: 8px;
      border: 8px solid currentColor;
      border-radius: 50%;
      animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
      border-color: currentColor transparent transparent transparent;
    }

    #preloader-spinner div:nth-child(1) {
      animation-delay: -0.45s;
    }

    #preloader-spinner div:nth-child(2) {
      animation-delay: -0.3s;
    }

    #preloader-spinner div:nth-child(3) {
      animation-delay: -0.15s;
    }

    @keyframes lds-ring {
      0% {
        transform: rotate(0deg);
      }

      100% {
        transform: rotate(360deg);
      }
    }

    /* Clean flat background – no polygon, ISPConfig uses a plain gray */
    .bg-poly {
      display: none;
    }

    /* Top-Right Controls */
    .top-controls {
      position: fixed;
      top: 16px;
      right: 20px;
      display: flex;
      gap: 10px;
      align-items: center;
      z-index: 100;
    }

    .icon-btn {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background .2s;
      color: var(--text);
    }

    .icon-btn:hover {
      background: var(--icon-bth)
    }

    .icon-btn svg {
      width: 18px;
      height: 18px;
      stroke: var(--text);
    }

    /* Language Dropdown */
    .lang-dropdown-wrap {
      position: relative
    }

    .lang-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      border-radius: 18px;
      padding: 6px 14px;
      color: var(--text);
      font-family: inherit;
      font-size: .82rem;
      font-weight: 500;
      cursor: pointer;
      transition: background .2s;
    }

    .lang-btn:hover {
      background: var(--icon-bth)
    }

    .lang-btn svg {
      width: 15px;
      height: 15px;
      opacity: .85
    }

    .lang-dropdown {
      position: absolute;
      top: calc(100% + 6px);
      right: 0;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 12px;
      padding: 6px;
      width: 170px;
      max-height: 260px;
      overflow-y: auto;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .35);
      display: none;
      z-index: 200;
    }

    .lang-dropdown.show {
      display: block
    }

    .lang-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 7px 10px;
      border: none;
      background: transparent;
      color: var(--text);
      font-family: inherit;
      font-size: .82rem;
      border-radius: 6px;
      cursor: pointer;
      text-align: left;
      transition: background .15s;
    }

    .lang-item:hover {
      background: var(--input-bg)
    }

    .lang-item.active {
      color: #cc0000;
      font-weight: 600
    }

    /* Card */
    .card {
      position: relative;
      z-index: 1;
      background: var(--card);
      border: 1px solid #d0d5dd;
      border-radius: 4px;
      padding: 0;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, .05);
      overflow: hidden;
      transition: background .35s, border-color .35s;
    }

    [data-theme="dark"] .card {
      border-color: rgba(255,255,255,.12);
      box-shadow: 0 8px 32px rgba(0, 0, 0, .4);
    }

    /* Logo Header - exact match to ISPConfig screen */
    .card-header {
      background: linear-gradient(to bottom, #f9fafb, #ebeef2);
      border-bottom: 1px solid #d0d5dd;
      padding: 24px 20px;
      display: flex;
      justify-content: center;
      align-items: center;
      gap: 12px;
    }

    [data-theme="dark"] .card-header {
      background: #1c2230;
      border-bottom-color: rgba(255,255,255,.12);
    }

    .logo-icon {
      width: 50px;
      height: 38px;
    }

    .logo-text h1 {
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: .02em;
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1;
    }

    .logo-text h1 .isp-red {
      color: #cc0000;
    }

    .logo-text h1 .config-dark {
      color: #4e555d;
    }

    [data-theme="dark"] .logo-text h1 .config-dark {
      color: #cbd5e1;
    }

    .card-body {
      padding: 24px 30px 28px;
    }

    /* Alert */
    .alert {
      border-radius: 10px;
      padding: 12px 14px;
      font-size: .85rem;
      margin-bottom: 20px;
      border: 1px solid;
      line-height: 1.5;
    }

    .alert-error {
      background: var(--err-bg);
      border-color: var(--err-b);
      color: var(--err-text)
    }

    .alert-success {
      background: var(--ok-bg);
      border-color: var(--ok-b);
      color: var(--ok-text)
    }

    .alert a {
      color: inherit;
      font-weight: 600
    }

    /* Form */
    .field {
      margin-bottom: 18px
    }

    label {
      display: block;
      font-size: .82rem;
      font-weight: 500;
      margin-bottom: 6px;
      color: var(--sub)
    }

    .input-wrap {
      position: relative
    }

    input[type=text],
    input[type=email],
    input[type=password] {
      width: 100%;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 3px;
      color: var(--text);
      font-family: inherit;
      font-size: .88rem;
      padding: 8px 12px;
      outline: none;
      transition: border-color .2s, box-shadow .2s;
    }

    input:not([type="checkbox"]):focus {
      border-color: var(--input-bh);
      box-shadow: 0 0 0 2px rgba(204,0,0,.12);
    }

    input::placeholder {
      color: var(--sub);
      opacity: .7
    }

    .eye-btn {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      color: var(--sub);
      display: flex;
      padding: 4px;
      transition: color .2s;
    }

    .eye-btn:hover {
      color: var(--text)
    }

    .eye-btn svg.hide-icon {
      display: none
    }

    .pw-field {
      padding-right: 42px !important
    }

    .copy-pw-btn {
      background: none;
      border: 1px solid var(--input-b);
      border-radius: 6px;
      cursor: pointer;
      color: var(--sub);
      font-size: 0.78rem;
      padding: 4px 10px;
      display: flex;
      align-items: center;
      gap: 5px;
      transition: all .2s;
      white-space: nowrap;
    }

    .copy-pw-btn:hover {
      color: var(--text);
      border-color: var(--btn)
    }

    .copy-pw-btn.copied {
      color: #2ecc71;
      border-color: #2ecc71
    }

    /* Row */
    .field-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px
    }

    .btn-wrap {
      display: flex;
      justify-content: flex-end;
      margin-top: 18px;
    }

    .btn {
      width: auto;
      min-width: 80px;
      padding: 6px 16px;
      background: linear-gradient(to bottom, #ffffff, #e4e7eb);
      color: #333333;
      border: 1px solid #cccccc;
      border-radius: 3px;
      font-family: inherit;
      font-size: .85rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all .15s ease;
    }

    .btn:hover {
      background: linear-gradient(to bottom, #f4f6f8, #dadfe5);
      border-color: #bbbbbb;
      color: #111111;
    }

    .btn:active {
      background: #d5dade;
    }

    .btn:disabled {
      opacity: .6;
      cursor: not-allowed
    }

    .spinner {
      width: 18px;
      height: 18px;
      border: 2px solid rgba(255, 255, 255, .4);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin .7s linear infinite;
      display: none;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg)
      }
    }

    /* Password Strength Meter */
    .pw-meter {
      margin-top: 10px;
    }

    .pw-meter-bar {
      height: 4px;
      background: var(--input-bg);
      border-radius: 2px;
      overflow: hidden;
      border: 1px solid var(--input-b);
    }

    .pw-meter-fill {
      height: 100%;
      width: 0%;
      transition: width 0.3s ease, background-color 0.3s ease;
    }

    .pw-meter-text {
      font-size: 0.75rem;
      margin-top: 4px;
      color: var(--sub);
      display: flex;
      justify-content: space-between;
    }

    /* Password Checklist */
    .pw-checklist {
      list-style: none;
      margin-top: 10px;
      padding: 0;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px 10px;
    }
    .pw-check-item {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 0.74rem;
      color: var(--sub);
      transition: color 0.2s;
    }
    .pw-check-item .check-icon {
      width: 15px; height: 15px;
      border-radius: 50%;
      border: 1.5px solid var(--sub);
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0;
      transition: background 0.2s, border-color 0.2s;
      font-size: 0.65rem;
    }
    .pw-check-item.ok { color: var(--ok-text); }
    .pw-check-item.ok .check-icon {
      background: var(--ok-text);
      border-color: var(--ok-text);
      color: #fff;
    }

    /* HIBP Status */
    .hibp-status {
      font-size: 0.78rem;
      margin-top: 8px;
      padding: 6px 10px;
      border-radius: 6px;
      display: none;
    }
    .hibp-status.checking { display:block; color: var(--sub); }
    .hibp-status.warning  { display:block; color: var(--err-text); background: var(--err-bg); border: 1px solid var(--err-b); }
    .hibp-status.ok       { display:block; color: var(--ok-text); background: var(--ok-bg); border: 1px solid var(--ok-b); }


    .help-fab-wrap {
      position: fixed;
      bottom: 20px;
      left: 20px;
      z-index: 100;
    }

    .help-fab {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      border-radius: 20px;
      padding: 8px 16px;
      color: var(--text);
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s;
    }

    .help-fab:hover {
      background: var(--icon-bth);
    }

    .help-fab svg {
      color: #cc0000;
      stroke: #cc0000;
    }

    .help-menu {
      position: absolute;
      bottom: calc(100% + 10px);
      left: 0;
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 12px;
      padding: 6px;
      width: 180px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .35);
      display: none;
      flex-direction: column;
      z-index: 200;
    }

    .help-menu.show {
      display: flex;
      animation: fadeIn 0.2s ease-out;
    }

    .help-menu a {
      padding: 8px 12px;
      color: var(--text);
      text-decoration: none;
      font-size: 0.85rem;
      border-radius: 6px;
      transition: background 0.15s;
    }

    .help-menu a:hover {
      background: var(--input-bg);
    }

    .login-link {
      text-align: center;
      margin-top: 16px;
      font-size: .82rem;
      color: var(--sub)
    }

    .login-link a {
      color: #cc0000;
      text-decoration: none;
      font-weight: 500
    }

    .login-link a:hover {
      text-decoration: underline
    }

    /* ALTCHA Widget Theming */
    altcha-widget {
      --altcha-color-border: var(--input-b);
      --altcha-color-border-focus: var(--input-bh);
      --altcha-color-background: var(--input-bg);
      --altcha-color-text: var(--text);
      --altcha-color-text-secondary: var(--sub);
      --altcha-border-radius: 8px;
      width: 100%;
      margin-top: 18px;
      display: block;
    }

    /* ── Cookie Banner ──────────────────────────────────────────────────────── */
    #cookieBanner {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 9998;
      background: rgba(255, 255, 255, 0.97);
      border-top: 1px solid #d0d5dd;
      padding: 14px 24px;
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
      justify-content: space-between;
      transform: translateY(100%);
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 -2px 12px rgba(0,0,0,.08);
    }

    #cookieBanner.visible {
      transform: translateY(0);
    }

    [data-theme="dark"] #cookieBanner {
      background: rgba(30, 35, 50, 0.97);
      border-top: 1px solid rgba(255,255,255,.1);
    }

    #cookieBanner p {
      font-size: 0.83rem;
      color: var(--sub);
      line-height: 1.5;
      margin: 0;
      flex: 1;
      min-width: 200px;
    }

    #cookieAcceptBtn {
      background: #cc0000;
      color: #fff;
      border: none;
      border-radius: 4px;
      padding: 9px 22px;
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
      white-space: nowrap;
      flex-shrink: 0;
    }

    #cookieAcceptBtn:hover {
      background: #a80000;
    }

    #cookieAcceptBtn:active {
      transform: scale(0.97);
    }

    /* ── Accessibility Widget ───────────────────────────────────────────────── */
    #a11yWidget {
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 500;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
    }

    #a11yToggleBtn {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: #ffffff;
      border: 1px solid #d0d5dd;
      color: #cc0000;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.12);
      transition: background 0.2s, transform 0.2s, box-shadow 0.2s;
    }

    #a11yToggleBtn:hover {
      background: #f8f9fa;
      transform: scale(1.06);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.16);
    }

    #a11yToggleBtn svg {
      width: 20px;
      height: 20px;
      stroke: #cc0000;
    }

    #a11yPanel {
      background: var(--card);
      border: 1px solid var(--card-b);
      border-radius: 14px;
      padding: 14px 16px;
      width: 210px;
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.35);
      display: none;
      flex-direction: column;
      gap: 10px;
      animation: fadeIn 0.2s ease-out;
    }

    #a11yPanel.open {
      display: flex;
    }

    #a11yPanel h4 {
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--sub);
      text-transform: uppercase;
      letter-spacing: 0.1em;
      margin: 0 0 4px;
      border-bottom: 1px solid var(--card-b);
      padding-bottom: 8px;
    }

    .a11y-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .a11y-label {
      font-size: 0.82rem;
      color: var(--text);
    }

    .a11y-controls {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .a11y-btn {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      color: var(--text);
      font-size: 0.9rem;
      font-family: inherit;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background 0.15s;
    }

    .a11y-btn:hover {
      background: var(--icon-bth);
    }

    .a11y-toggle-switch {
      position: relative;
      width: 36px;
      height: 20px;
      cursor: pointer;
    }

    .a11y-toggle-switch input {
      opacity: 0;
      width: 0;
      height: 0;
      position: absolute;
    }

    .a11y-slider {
      position: absolute;
      inset: 0;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 10px;
      transition: background 0.2s;
    }

    .a11y-slider::before {
      content: '';
      position: absolute;
      width: 14px;
      height: 14px;
      left: 2px;
      top: 2px;
      background: var(--sub);
      border-radius: 50%;
      transition: transform 0.2s, background 0.2s;
    }

    .a11y-toggle-switch input:checked + .a11y-slider {
      background: var(--btn);
      border-color: var(--btn);
    }

    .a11y-toggle-switch input:checked + .a11y-slider::before {
      transform: translateX(16px);
      background: #fff;
    }

    #a11yFontSize {
      font-size: 0.78rem;
      color: var(--sub);
      min-width: 22px;
      text-align: center;
    }
  </style>
  <script>
const I18N = {
  "en": {
    "name": "English",
    "subtitle": "web control panel",
    "username": "Username",
    "username_ph": "4–8 chars, a-z 0-9",
    "email": "Email Address",
    "email_ph": "user@example.com",
    "domain": "Domain",
    "domain_ph": "example.com",
    "password": "Password",
    "password_ph": "Min. 8 chars",
    "confirm": "Confirm",
    "confirm_ph": "Repeat",
    "register": "Register",
    "already_registered": "Already registered?",
    "to_login": "To Login",
    "to_panel": "Go to Panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Weak",
    "pw_medium": "Medium",
    "pw_strong": "Strong",
    "please_wait": "Please wait...",
    "success_heading": "Account Created!",
    "generate": "Generate",
    "maintenance_heading": "Maintenance Mode",
    "maintenance_text": "New registrations are temporarily paused for maintenance. Please check back later.",
    "tos_prefix": "I agree to the",
    "tos_link": "Terms of Service",
    "tos_and": "and",
    "privacy_link": "Privacy Policy",
    "did_you_mean": "Did you mean",
    "setup_2fa": "We recommend enabling Two-Factor Authentication (2FA) in the panel.",
    "copy_pw": "Copy",
    "need_help": "Need Help?",
    "contact_support": "Contact Support",
    "forgot_password": "Forgot Password?",
    "pw_req_length": "At least {n} characters",
    "pw_req_upper": "One uppercase letter (A-Z)",
    "pw_req_lower": "One lowercase letter (a-z)",
    "pw_req_number": "One number (0-9)",
    "email_mx_invalid": "The email domain does not appear to accept mail.",
    "pw_hibp_warning": "⚠️ This password appeared in {n} data breach(es).",
    "pw_hibp_ok": "✓ Password not found in known data breaches.",
    "pw_hibp_checking": "Checking password security...",
    "invite_code": "Invitation Code",
    "invite_code_ph": "Enter your invitation code",
    "invite_required": "An invitation code is required to register.",
    "invite_invalid": "Invalid or already used invitation code.",
    "demo_notice": "⏱ This is a demo account and will be automatically deleted after {n} hour(s)."
  },
  "de": {
    "name": "Deutsch",
    "subtitle": "Web-Control-Panel",
    "username": "Benutzername",
    "username_ph": "4–8 Zeichen, a-z 0-9",
    "email": "E-Mail-Adresse",
    "email_ph": "user@example.com",
    "domain": "Domain",
    "domain_ph": "example.com",
    "password": "Passwort",
    "password_ph": "Mind. 8 Zeichen",
    "confirm": "Bestätigen",
    "confirm_ph": "Wiederholen",
    "register": "Registrieren",
    "already_registered": "Bereits registriert?",
    "to_login": "Zum Login",
    "to_panel": "Zum Panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Schwach",
    "pw_medium": "Mittel",
    "pw_strong": "Stark",
    "please_wait": "Bitte warten...",
    "success_heading": "Konto erstellt!",
    "generate": "Erzeugen",
    "maintenance_heading": "Wartungsmodus",
    "maintenance_text": "Neu-Registrierungen sind wegen Wartungsarbeiten vorübergehend pausiert. Bitte versuche es später erneut.",
    "tos_prefix": "Ich akzeptiere die",
    "tos_link": "Nutzungsbedingungen",
    "tos_and": "und die",
    "privacy_link": "Datenschutzerklärung",
    "did_you_mean": "Meintest du",
    "setup_2fa": "Wir empfehlen, die Zwei-Faktor-Authentifizierung (2FA) im Panel zu aktivieren.",
    "copy_pw": "Kopieren",
    "need_help": "Brauchst du Hilfe?",
    "contact_support": "Support kontaktieren",
    "forgot_password": "Passwort vergessen?",
    "pw_req_length": "Mindestens {n} Zeichen",
    "pw_req_upper": "Ein Großbuchstabe (A-Z)",
    "pw_req_lower": "Ein Kleinbuchstabe (a-z)",
    "pw_req_number": "Eine Zahl (0-9)",
    "email_mx_invalid": "Die E-Mail-Domain scheint keine E-Mails zu empfangen.",
    "pw_hibp_warning": "⚠️ Dieses Passwort tauchte in {n} Datenlecks auf.",
    "pw_hibp_ok": "✓ Passwort in bekannten Datenlecks nicht gefunden.",
    "pw_hibp_checking": "Passwortsicherheit wird geprüft...",
    "invite_code": "Einladungscode",
    "invite_code_ph": "Gib deinen Einladungscode ein",
    "invite_required": "Für die Registrierung ist ein Einladungscode erforderlich.",
    "invite_invalid": "Ungültiger oder bereits verwendeter Einladungscode.",
    "demo_notice": "⏱ Dies ist ein Demo-Konto und wird nach {n} Stunde(n) automatisch gelöscht."
  },
  "bg": {
    "name": "Български",
    "subtitle": "уеб контролен панел",
    "username": "Потребителско име",
    "username_ph": "4–8 символа, a-z 0-9",
    "email": "Имейл адрес",
    "email_ph": "user@example.com",
    "domain": "Домейн",
    "domain_ph": "example.com",
    "password": "Парола",
    "password_ph": "Мин. 8 символа",
    "confirm": "Потвърждение",
    "confirm_ph": "Повторете",
    "register": "Регистрация",
    "already_registered": "Вече имате акаунт?",
    "to_login": "Към вход",
    "to_panel": "Към панела",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Слаба",
    "pw_medium": "Средна",
    "pw_strong": "Силна",
    "please_wait": "Моля изчакайте...",
    "success_heading": "Акаунтът е създаден!",
    "generate": "Генериране",
    "maintenance_heading": "Режим на поддръжка",
    "maintenance_text": "Новите регистрации са временно спрени поради поддръжка. Моля, опитайте по-късно.",
    "tos_prefix": "Съгласен съм с",
    "tos_link": "Условията за ползване",
    "tos_and": "и",
    "privacy_link": "Политиката за поверителност",
    "did_you_mean": "Имахте предвид",
    "setup_2fa": "Препоръчваме активиране на двуфакторна автентификация (2FA) в панела.",
    "copy_pw": "Копирай",
    "need_help": "Нужда от помощ?",
    "contact_support": "Връзка с поддръжката",
    "forgot_password": "Забравена парола?",
    "pw_req_length": "Поне {n} символа",
    "pw_req_upper": "Една главна буква (A-Z)",
    "pw_req_lower": "Една малка буква (a-z)",
    "pw_req_number": "Едно число (0-9)",
    "email_mx_invalid": "Домейнът на имейла не приема поща.",
    "pw_hibp_warning": "⚠️ Тази парола е открита в {n} пробива на данни.",
    "pw_hibp_ok": "✓ Паролата не е намерена в известни пробиви.",
    "pw_hibp_checking": "Проверка на сигурността на паролата...",
    "invite_code": "Код за покана",
    "invite_code_ph": "Въведете вашия код за покана",
    "invite_required": "За регистрация се изисква код за покана.",
    "invite_invalid": "Невалиден или използван код за покана.",
    "demo_notice": "⏱ Това е демо акаунт и ще бъде изтрит автоматично след {n} час(а)."
  },
  "pt-br": {
    "name": "Português (BR)",
    "subtitle": "painel de controle web",
    "username": "Nome de Usuário",
    "username_ph": "4–8 caract., a-z 0-9",
    "email": "Endereço de E-mail",
    "email_ph": "usuario@exemplo.com",
    "domain": "Domínio",
    "domain_ph": "exemplo.com",
    "password": "Senha",
    "password_ph": "Mín. 8 caract.",
    "confirm": "Confirmar Senha",
    "confirm_ph": "Repetir",
    "register": "Cadastrar",
    "already_registered": "Já tem uma conta?",
    "to_login": "Ir para o Login",
    "to_panel": "Ir para o Painel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Fraca",
    "pw_medium": "Média",
    "pw_strong": "Forte",
    "please_wait": "Aguarde...",
    "success_heading": "Conta Criada!",
    "generate": "Gerar",
    "maintenance_heading": "Modo de Manutenção",
    "maintenance_text": "Novos cadastros estão temporariamente suspensos para manutenção. Tente novamente mais tarde.",
    "tos_prefix": "Eu concordo com os",
    "tos_link": "Termos de Serviço",
    "tos_and": "e a",
    "privacy_link": "Política de Privacidade",
    "did_you_mean": "Você quis dizer",
    "setup_2fa": "Recomendamos ativar a Autenticação de Dois Fatores (2FA) no painel.",
    "copy_pw": "Copiar",
    "need_help": "Precisa de Ajuda?",
    "contact_support": "Contatar Suporte",
    "forgot_password": "Esqueceu a Senha?",
    "pw_req_length": "Pelo menos {n} caracteres",
    "pw_req_upper": "Uma letra maiúscula (A-Z)",
    "pw_req_lower": "Uma letra minúscula (a-z)",
    "pw_req_number": "Um número (0-9)",
    "email_mx_invalid": "O domínio do e-mail parece não aceitar mensagens.",
    "pw_hibp_warning": "⚠️ Esta senha apareceu em {n} vazamento(s) de dados.",
    "pw_hibp_ok": "✓ Senha não encontrada em vazamentos de dados conhecidos.",
    "pw_hibp_checking": "Verificando segurança da senha...",
    "invite_code": "Código de Convite",
    "invite_code_ph": "Digite seu código de convite",
    "invite_required": "Um código de convite é obrigatório para registrar.",
    "invite_invalid": "Código de convite inválido ou já utilizado.",
    "demo_notice": "⏱ Esta é uma conta de demonstração e será excluída automaticamente após {n} hora(s)."
  },
  "hr": {
    "name": "Hrvatski",
    "subtitle": "web upravljačka ploča",
    "username": "Korisničko ime",
    "username_ph": "4–8 znaka, a-z 0-9",
    "email": "E-mail adresa",
    "email_ph": "korisnik@primjer.com",
    "domain": "Domena",
    "domain_ph": "primjer.com",
    "password": "Lozinka",
    "password_ph": "Min. 8 znaka",
    "confirm": "Potvrdi lozinku",
    "confirm_ph": "Ponovi",
    "register": "Registriraj se",
    "already_registered": "Već ste registrirani?",
    "to_login": "Na prijavu",
    "to_panel": "Na upravljačku ploču",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Slaba",
    "pw_medium": "Srednja",
    "pw_strong": "Jaka",
    "please_wait": "Molimo pričekajte...",
    "success_heading": "Račun je izrađen!",
    "generate": "Generiraj",
    "maintenance_heading": "Način održavanja",
    "maintenance_text": "Nove registracije su privremeno pauzirane zbog održavanja. Pokušajte ponovno kasnije.",
    "tos_prefix": "Prihvaćam",
    "tos_link": "Uvjete pružanja usluge",
    "tos_and": "i",
    "privacy_link": "Pravila privatnosti",
    "did_you_mean": "Jeste li mislili",
    "setup_2fa": "Preporučujemo omogućenje dvofaktorske autentičnosti (2FA) na ploči.",
    "copy_pw": "Kopiraj",
    "need_help": "Trebate pomoć?",
    "contact_support": "Kontaktirajte podršku",
    "forgot_password": "Zaboravili ste lozinku?",
    "pw_req_length": "Najmanje {n} znakova",
    "pw_req_upper": "Jedno veliko slovo (A-Z)",
    "pw_req_lower": "Jedno malo slovo (a-z)",
    "pw_req_number": "Jedan broj (0-9)",
    "email_mx_invalid": "Domena e-pošte ne prima poruke.",
    "pw_hibp_warning": "⚠️ Ova lozinka se pojavila u {n} sigurnosnih proboja.",
    "pw_hibp_ok": "✓ Lozinka nije pronađena u poznatim probojima podataka.",
    "pw_hibp_checking": "Provjera sigurnosti lozinke...",
    "invite_code": "Kod pozivnice",
    "invite_code_ph": "Unesite vaš kod pozivnice",
    "invite_required": "Kod pozivnice je obavezan za registraciju.",
    "invite_invalid": "Nevažeći ili već iskorišten kod pozivnice.",
    "demo_notice": "⏱ Ovo je demo račun i automatski će se izbrisati nakon {n} sat(a)."
  },
  "cs": {
    "name": "Čeština",
    "subtitle": "webový ovládací panel",
    "username": "Uživatelské jméno",
    "username_ph": "4–8 znaků, a-z 0-9",
    "email": "E-mailová adresa",
    "email_ph": "uzivatel@example.com",
    "domain": "Doména",
    "domain_ph": "example.com",
    "password": "Heslo",
    "password_ph": "Min. 8 znaků",
    "confirm": "Potvrzení hesla",
    "confirm_ph": "Opakovat",
    "register": "Registrovat se",
    "already_registered": "Již máte účet?",
    "to_login": "K přihlášení",
    "to_panel": "Do panelu",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Slabé",
    "pw_medium": "Střední",
    "pw_strong": "Silné",
    "please_wait": "Prosím čekejte...",
    "success_heading": "Účet byl vytvořen!",
    "generate": "Generovat",
    "maintenance_heading": "Režim údržby",
    "maintenance_text": "Nové registrace jsou z důvodu údržby dočasně pozastaveny. Zkuste to prosím později.",
    "tos_prefix": "Souhlasím s",
    "tos_link": "Podmínkami služby",
    "tos_and": "a",
    "privacy_link": "Zásadami ochrany osobních údajů",
    "did_you_mean": "Měli jste na mysli",
    "setup_2fa": "Doporučujeme aktivovat dvoufázové ověření (2FA) v ovládacím panelu.",
    "copy_pw": "Kopírovat",
    "need_help": "Potřebujete pomoc?",
    "contact_support": "Kontaktovat podporu",
    "forgot_password": "Zapomněli jste heslo?",
    "pw_req_length": "Alespoň {n} znaků",
    "pw_req_upper": "Jedno velké písmeno (A-Z)",
    "pw_req_lower": "Jedno malé písmeno (a-z)",
    "pw_req_number": "Jedno číslo (0-9)",
    "email_mx_invalid": "E-mailová doména neuchovává ani nepříjímá poštu.",
    "pw_hibp_warning": "⚠️ Toto heslo se objevilo v {n} únikách dat.",
    "pw_hibp_ok": "✓ Heslo nebylo nalezeno v známých únikách dat.",
    "pw_hibp_checking": "Kontrola bezpečnosti hesla...",
    "invite_code": "Pozvánkový kód",
    "invite_code_ph": "Zadejte váš pozvánkový kód",
    "invite_required": "Pro registraci je vyžadován pozvánkový kód.",
    "invite_invalid": "Neplatný nebo již použitý pozvánkový kód.",
    "demo_notice": "⏱ Toto je demo účet a bude automaticky smazán po {n} hodině/hodinách."
  },
  "nl": {
    "name": "Nederlands",
    "subtitle": "web controlepaneel",
    "username": "Gebruikersnaam",
    "username_ph": "4–8 tekens, a-z 0-9",
    "email": "E-mailadres",
    "email_ph": "gebruiker@voorbeeld.nl",
    "domain": "Domein",
    "domain_ph": "voorbeeld.nl",
    "password": "Wachtwoord",
    "password_ph": "Min. 8 tekens",
    "confirm": "Bevestigen",
    "confirm_ph": "Herhalen",
    "register": "Registreren",
    "already_registered": "Al geregistreerd?",
    "to_login": "Naar inloggen",
    "to_panel": "Naar het paneel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Zwak",
    "pw_medium": "Gemiddeld",
    "pw_strong": "Sterk",
    "please_wait": "Even geduld...",
    "success_heading": "Account aangemaakt!",
    "generate": "Genereren",
    "maintenance_heading": "Onderhoudsmodus",
    "maintenance_text": "Nieuwe registraties zijn tijdelijk onderbroken voor onderhoud. Probeer het later opnieuw.",
    "tos_prefix": "Ik ga akkoord met de",
    "tos_link": "Algemene Voorwaarden",
    "tos_and": "en het",
    "privacy_link": "Privacybeleid",
    "did_you_mean": "Bedoelde je",
    "setup_2fa": "We raden aan om Twee-Factor Authenticatie (2FA) in te schakelen in het paneel.",
    "copy_pw": "Kopiëren",
    "need_help": "Hulp nodig?",
    "contact_support": "Support contacteren",
    "forgot_password": "Wachtwoord vergeten?",
    "pw_req_length": "Minimaal {n} tekens",
    "pw_req_upper": "Eén hoofdletter (A-Z)",
    "pw_req_lower": "Eén kleine letter (a-z)",
    "pw_req_number": "Eén cijfer (0-9)",
    "email_mx_invalid": "Het e-maildomein lijkt geen e-mail te accepteren.",
    "pw_hibp_warning": "⚠️ Dit wachtwoord is gevonden in {n} datalek(ken).",
    "pw_hibp_ok": "✓ Wachtwoord niet gevonden in bekende datalekken.",
    "pw_hibp_checking": "Wachtwoordbeveiliging controleren...",
    "invite_code": "Uitnodigingscode",
    "invite_code_ph": "Voer je uitnodigingscode in",
    "invite_required": "Een uitnodigingscode is vereist om te registreren.",
    "invite_invalid": "Ongeldige of reeds gebruikte uitnodigingscode.",
    "demo_notice": "⏱ Dit is een demo-account en wordt automatisch verwijderd na {n} uur."
  },
  "fi": {
    "name": "Suomi",
    "subtitle": "web-hallintapaneeli",
    "username": "Käyttäjätunnus",
    "username_ph": "4–8 merkkiä, a-z 0-9",
    "email": "Sähköpostiosoite",
    "email_ph": "kayttaja@esimerkki.fi",
    "domain": "Verkkotunnus",
    "domain_ph": "esimerkki.fi",
    "password": "Salasana",
    "password_ph": "Väh. 8 merkkiä",
    "confirm": "Vahvista salasana",
    "confirm_ph": "Toista",
    "register": "Rekisteröidy",
    "already_registered": "Onko sinulla jo tili?",
    "to_login": "Kirjautumiseen",
    "to_panel": "Paneeliin",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Heikko",
    "pw_medium": "Keskiverto",
    "pw_strong": "Vahva",
    "please_wait": "Odota hetki...",
    "success_heading": "Tili luotu!",
    "generate": "Luo salasana",
    "maintenance_heading": "Huoltotila",
    "maintenance_text": "Uudet rekisteröinnit on tilapäisesti keskeytetty huoltotöiden vuoksi. Yritä myöhemmin uudelleen.",
    "tos_prefix": "Hyväksyn",
    "tos_link": "Käyttöehdot",
    "tos_and": "ja",
    "privacy_link": "Tietosuojakäytännön",
    "did_you_mean": "Tarkoititko",
    "setup_2fa": "Suosittelemme kaksivaiheisen tunnistautumisen (2FA) ottamista käyttöön paneelissa.",
    "copy_pw": "Kopioi",
    "need_help": "Tarvitsetko apua?",
    "contact_support": "Ota yhteyttä tukeen",
    "forgot_password": "Unohtuiko salasana?",
    "pw_req_length": "Vähintään {n} merkkiä",
    "pw_req_upper": "Yksi isokirjain (A-Z)",
    "pw_req_lower": "Yksi pieni kirjain (a-z)",
    "pw_req_number": "Yksi numero (0-9)",
    "email_mx_invalid": "Sähköpostiverkkotunnus ei näytä vastaanottavan postia.",
    "pw_hibp_warning": "⚠️ Tämä salasana on löytynyt {n} tietovuodosta.",
    "pw_hibp_ok": "✓ Salasanaa ei löytynyt tunnetuista tietovuodoista.",
    "pw_hibp_checking": "Tarkistetaan salasanan turvallisuutta...",
    "invite_code": "Kutsukoodi",
    "invite_code_ph": "Syötä kutsukoodisi",
    "invite_required": "Rekisteröitymiseen tarvitaan kutsukoodi.",
    "invite_invalid": "Virheellinen tai jo käytetty kutsukoodi.",
    "demo_notice": "⏱ Tämä on demotili ja se poistetaan automaattisesti {n} tunnin kuluttua."
  },
  "fr": {
    "name": "Français",
    "subtitle": "panneau de contrôle web",
    "username": "Nom d'utilisateur",
    "username_ph": "4–8 caract., a-z 0-9",
    "email": "Adresse e-mail",
    "email_ph": "user@example.com",
    "domain": "Domaine",
    "domain_ph": "example.com",
    "password": "Mot de passe",
    "password_ph": "Min. 8 caract.",
    "confirm": "Confirmer",
    "confirm_ph": "Répéter",
    "register": "S'inscrire",
    "already_registered": "Déjà inscrit ?",
    "to_login": "Connexion",
    "to_panel": "Accéder au panneau",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Faible",
    "pw_medium": "Moyen",
    "pw_strong": "Fort",
    "please_wait": "Veuillez patienter...",
    "success_heading": "Compte créé !",
    "generate": "Générer",
    "maintenance_heading": "Mode maintenance",
    "maintenance_text": "Les nouvelles inscriptions sont temporairement suspendues pour maintenance. Veuillez réessayer plus tard.",
    "tos_prefix": "J'accepte les",
    "tos_link": "Conditions d'utilisation",
    "tos_and": "et la",
    "privacy_link": "Politique de confidentialité",
    "did_you_mean": "Vouliez-vous dire",
    "setup_2fa": "Nous vous recommandons d'activer l'authentification à deux facteurs (2FA) dans le panneau.",
    "copy_pw": "Copier",
    "need_help": "Besoin d'aide ?",
    "contact_support": "Contacter le support",
    "forgot_password": "Mot de passe oublié ?",
    "pw_req_length": "Au moins {n} caractères",
    "pw_req_upper": "Une lettre majuscule (A-Z)",
    "pw_req_lower": "Une lettre minuscule (a-z)",
    "pw_req_number": "Un chiffre (0-9)",
    "email_mx_invalid": "Le domaine e-mail ne semble pas recevoir de courriels.",
    "pw_hibp_warning": "⚠️ Ce mot de passe est apparu dans {n} fuites de données.",
    "pw_hibp_ok": "✓ Mot de passe non trouvé dans les fuites de données connues.",
    "pw_hibp_checking": "Vérification de la sécurité du mot de passe...",
    "invite_code": "Code d'invitation",
    "invite_code_ph": "Entrez votre code d'invitation",
    "invite_required": "Un code d'invitation est requis pour s'inscrire.",
    "invite_invalid": "Code d'invitation invalide ou déjà utilisé.",
    "demo_notice": "⏱ Ce compte de démonstration sera automatiquement supprimé après {n} heure(s)."
  },
  "el": {
    "name": "Ελληνικά",
    "subtitle": "πίνακας ελέγχου web",
    "username": "Όνομα χρήστη",
    "username_ph": "4–8 χαρακτήρες, a-z 0-9",
    "email": "Διεύθυνση Email",
    "email_ph": "user@example.com",
    "domain": "Domain",
    "domain_ph": "example.com",
    "password": "Κωδικός πρόσβασης",
    "password_ph": "Τουλάχ. 8 χαρακτήρες",
    "confirm": "Επιβεβαίωση",
    "confirm_ph": "Επανάληψη",
    "register": "Εγγραφή",
    "already_registered": "Έχετε ήδη λογαριασμό;",
    "to_login": "Σύνδεση",
    "to_panel": "Μετάβαση στο Panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Αδύναμος",
    "pw_medium": "Μεσαίος",
    "pw_strong": "Ισχυρός",
    "please_wait": "Παρακαλώ περιμένετε...",
    "success_heading": "Ο λογαριασμός δημιουργήθηκε!",
    "generate": "Δημιουργία",
    "maintenance_heading": "Function Συντήρησης",
    "maintenance_text": "Οι νέες εγγραφές έχουν ανασταλεί προσωρινά για συντήρηση. Παρακαλώ δοκιμάστε ξανά αργότερα.",
    "tos_prefix": "Συμφωνώ με τους",
    "tos_link": "Όρους Χρήσης",
    "tos_and": "και την",
    "privacy_link": "Πολιτική Απορρήτου",
    "did_you_mean": "Μήπως εννοείτε",
    "setup_2fa": "Συνιστούμε την ενεργοποίηση ελέγχου ταυτότητας δύο παραγόντων (2FA) στο panel.",
    "copy_pw": "Αντιγραφή",
    "need_help": "Χρειάζεστε βοήθεια;",
    "contact_support": "Επικοινωνία με την Υποστήριξη",
    "forgot_password": "Ξεχάσατε τον κωδικό;",
    "pw_req_length": "Τουλάχιστον {n} χαρακτήρες",
    "pw_req_upper": "Ένα κεφαλαίο γράμμα (A-Z)",
    "pw_req_lower": "Ένα πεζό γράμμα (a-z)",
    "pw_req_number": "Ένας αριθμός (0-9)",
    "email_mx_invalid": "Το domain του email δεν φαίνεται να δέχεται αλληλογραφία.",
    "pw_hibp_warning": "⚠️ Αυτός ο κωδικός έχει βρεθεί σε {n} διαρροές δεδομένων.",
    "pw_hibp_ok": "✓ Ο κωδικός δεν βρέθηκε σε γνωστές διαρροές.",
    "pw_hibp_checking": "Έλεγχος ασφάλειας κωδικού...",
    "invite_code": "Κωδικός πρόσκλησης",
    "invite_code_ph": "Εισάγετε τον κωδικό πρόσκλησης",
    "invite_required": "Απαιτείται κωδικός πρόσκλησης για την εγγραφή.",
    "invite_invalid": "Μη έγκυρος ή ήδη χρησιμοποιημένος κωδικός πρόσκλησης.",
    "demo_notice": "⏱ Αυτός είναι ένας δοκιμαστικός λογαριασμός και θα διαγραφεί αυτόματα μετά από {n} ώρα/ώρες."
  },
  "hu": {
    "name": "Magyar",
    "subtitle": "webes vezérlőpult",
    "username": "Felhasználónév",
    "username_ph": "4–8 karakter, a-z 0-9",
    "email": "E-mail cím",
    "email_ph": "felhasznalo@pelda.hu",
    "domain": "Domain",
    "domain_ph": "pelda.hu",
    "password": "Jelszó",
    "password_ph": "Min. 8 karakter",
    "confirm": "Jelszó megerősítése",
    "confirm_ph": "Ismétlés",
    "register": "Regisztráció",
    "already_registered": "Már van fiókja?",
    "to_login": "Bejelentkezéshez",
    "to_panel": "Ugrás a vezérlőpultra",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Gyenge",
    "pw_medium": "Közepes",
    "pw_strong": "Erős",
    "please_wait": "Kérjük, várjon...",
    "success_heading": "Fiók létrehozva!",
    "generate": "Generálás",
    "maintenance_heading": "Karbantartási mód",
    "maintenance_text": "Új regisztrációk karbantartás miatt ideiglenesen szünetelnek. Kérjük, próbálja újra később.",
    "tos_prefix": "Elfogadom a",
    "tos_link": "Felhasználási feltételeket",
    "tos_and": "és az",
    "privacy_link": "Adatvédelmi irányelveket",
    "did_you_mean": "Erre gondolt",
    "setup_2fa": "Javasoljuk a kétfaktoros hitelesítés (2FA) engedélyezését a vezérlőpulton.",
    "copy_pw": "Másolás",
    "need_help": "Segítségre van szüksége?",
    "contact_support": "Kapcsolatfelvétel a támogatással",
    "forgot_password": "Elfelejtette a jelszót?",
    "pw_req_length": "Legalább {n} karakter",
    "pw_req_upper": "Egy nagybetű (A-Z)",
    "pw_req_lower": "Egy kisbetű (a-z)",
    "pw_req_number": "Egy szám (0-9)",
    "email_mx_invalid": "Az e-mail domain úgy tűnik, nem fogad leveleket.",
    "pw_hibp_warning": "⚠️ Ez a jelszó {n} kiszivárgott adatbázisban szerepel.",
    "pw_hibp_ok": "✓ A jelszó nem található az ismert kiszivárgásokban.",
    "pw_hibp_checking": "Jelszó biztonságának ellenőrzése...",
    "invite_code": "Meghívókód",
    "invite_code_ph": "Adja meg a meghívókódot",
    "invite_required": "A regisztrációhoz meghívókód szükséges.",
    "invite_invalid": "Érvénytelen vagy már felhasznált meghívókód.",
    "demo_notice": "⏱ Ez egy demó fiók, és {n} óra múlva automatikusan törlődik."
  },
  "id": {
    "name": "Bahasa Indonesia",
    "subtitle": "panel kontrol web",
    "username": "Nama Pengguna",
    "username_ph": "4–8 karakter, a-z 0-9",
    "email": "Alamat Email",
    "email_ph": "pengguna@contoh.com",
    "domain": "Domain",
    "domain_ph": "contoh.com",
    "password": "Kata Sandi",
    "password_ph": "Min. 8 karakter",
    "confirm": "Konfirmasi Kata Sandi",
    "confirm_ph": "Ulangi",
    "register": "Daftar",
    "already_registered": "Sudah punya akun?",
    "to_login": "Ke Halaman Login",
    "to_panel": "Ke Panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Lemah",
    "pw_medium": "Sedang",
    "pw_strong": "Kuat",
    "please_wait": "Mohon tunggu...",
    "success_heading": "Akun Berhasil Dibuat!",
    "generate": "Buat Otomatis",
    "maintenance_heading": "Mode Pemeliharaan",
    "maintenance_text": "Pendaftaran baru dihentikan sementara untuk pemeliharaan. Silakan coba lagi nanti.",
    "tos_prefix": "Saya menyetujui",
    "tos_link": "Syarat dan Ketentuan",
    "tos_and": "dan",
    "privacy_link": "Kebijakan Privasi",
    "did_you_mean": "Maksud Anda",
    "setup_2fa": "Kami menyarankan untuk mengaktifkan Otentikasi Dua Faktor (2FA) di panel.",
    "copy_pw": "Salin",
    "need_help": "Butuh Bantuan?",
    "contact_support": "Hubungi Dukungan",
    "forgot_password": "Lupa Kata Sandi?",
    "pw_req_length": "Minimal {n} karakter",
    "pw_req_upper": "Satu huruf besar (A-Z)",
    "pw_req_lower": "Satu huruf kecil (a-z)",
    "pw_req_number": "Satu angka (0-9)",
    "email_mx_invalid": "Domain email tampaknya tidak dapat menerima pesan.",
    "pw_hibp_warning": "⚠️ Kata sandi ini telah ditemukan dalam {n} kebocoran data.",
    "pw_hibp_ok": "✓ Kata sandi aman dan tidak ditemukan dalam kebocoran data.",
    "pw_hibp_checking": "Memeriksa keamanan kata sandi...",
    "invite_code": "Kode Undangan",
    "invite_code_ph": "Masukkan kode undangan Anda",
    "invite_required": "Kode undangan diperlukan untuk mendaftar.",
    "invite_invalid": "Kode undangan tidak valid atau sudah digunakan.",
    "demo_notice": "⏱ Ini adalah akun demo dan akan dihapus secara otomatis setelah {n} jam."
  },
  "it": {
    "name": "Italiano",
    "subtitle": "pannello di controllo web",
    "username": "Nome utente",
    "username_ph": "4–8 caract., a-z 0-9",
    "email": "Indirizzo Email",
    "email_ph": "utente@esempio.it",
    "domain": "Dominio",
    "domain_ph": "esempio.it",
    "password": "Password",
    "password_ph": "Min. 8 caratteri",
    "confirm": "Conferma Password",
    "confirm_ph": "Ripeti",
    "register": "Registrati",
    "already_registered": "Sei già registrato?",
    "to_login": "Vai al Login",
    "to_panel": "Vai al Pannello",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Debole",
    "pw_medium": "Media",
    "pw_strong": "Forte",
    "please_wait": "Attendere prego...",
    "success_heading": "Account Creato!",
    "generate": "Genera",
    "maintenance_heading": "Modalità Manutenzione",
    "maintenance_text": "Le nuove registrazioni sono temporaneamente sospese per manutenzione. Riprova più tardi.",
    "tos_prefix": "Accetto i",
    "tos_link": "Termini di Servizio",
    "tos_and": "e la",
    "privacy_link": "Informativa sulla Privacy",
    "did_you_mean": "Intendevi",
    "setup_2fa": "Consigliamo di abilitare l'Autenticazione a Due Fattori (2FA) nel pannello.",
    "copy_pw": "Copia",
    "need_help": "Serve aiuto?",
    "contact_support": "Contatta il Supporto",
    "forgot_password": "Password dimenticata?",
    "pw_req_length": "Almeno {n} caratteri",
    "pw_req_upper": "Una lettera maiuscola (A-Z)",
    "pw_req_lower": "Una lettera minuscola (a-z)",
    "pw_req_number": "Un numero (0-9)",
    "email_mx_invalid": "Il dominio e-mail non sembra accettare messaggi.",
    "pw_hibp_warning": "⚠️ Questa password è apparsa in {n} violazioni di dati.",
    "pw_hibp_ok": "✓ Password non trovata in violazioni di dati note.",
    "pw_hibp_checking": "Verifica della sicurezza della password...",
    "invite_code": "Codice Invito",
    "invite_code_ph": "Inserisci il tuo codice invito",
    "invite_required": "Un codice invito è richiesto per registrarsi.",
    "invite_invalid": "Codice invito non valido o già utilizzato.",
    "demo_notice": "⏱ Questo è un account demo e verrà eliminato automaticamente dopo {n} ora/e."
  },
  "ja": {
    "name": "日本語",
    "subtitle": "Webコントロールパネル",
    "username": "ユーザー名",
    "username_ph": "4〜8文字、半角英数字",
    "email": "メールアドレス",
    "email_ph": "user@example.jp",
    "domain": "ドメイン",
    "domain_ph": "example.jp",
    "password": "パスワード",
    "password_ph": "8文字以上",
    "confirm": "パスワード確認",
    "confirm_ph": "再入力",
    "register": "新規登録",
    "already_registered": "既にアカウントをお持ちですか？",
    "to_login": "ログインへ",
    "to_panel": "コントロールパネルへ",
    "pw_hint": "英大文字・小文字・数字",
    "pw_weak": "弱い",
    "pw_medium": "普通",
    "pw_strong": "強い",
    "please_wait": "処理中...",
    "success_heading": "アカウントが作成されました！",
    "generate": "自動生成",
    "maintenance_heading": "メンテナンス中",
    "maintenance_text": "現在メンテナンス中のため、新規登録を停止しております。後ほど再度お試しください。",
    "tos_prefix": "利用規約に",
    "tos_link": "利用規約",
    "tos_and": "および",
    "privacy_link": "プライバシーポリシー",
    "did_you_mean": "もしかして",
    "setup_2fa": "パネルにログイン後、2要素認証（2FA）を有効にすることを推奨します。",
    "copy_pw": "コピー",
    "need_help": "ヘルプが必要ですか？",
    "contact_support": "サポートに連絡",
    "forgot_password": "パスワードをお忘れですか？",
    "pw_req_length": "{n}文字以上",
    "pw_req_upper": "英大文字を含む (A-Z)",
    "pw_req_lower": "英小文字を含む (a-z)",
    "pw_req_number": "数字を含む (0-9)",
    "email_mx_invalid": "メールのドメインが存在しないか、受信できません。",
    "pw_hibp_warning": "⚠️ このパスワードは{n}件のデータ流出で確認されています。",
    "pw_hibp_ok": "✓ パスワードの流出は確認されませんでした。",
    "pw_hibp_checking": "パスワードの me 安全性を確認中...",
    "invite_code": "招待コード",
    "invite_code_ph": "招待コードを入力してください",
    "invite_required": "登録には招待コードが必要です。",
    "invite_invalid": "無効または使用済みの招待コードです。",
    "demo_notice": "⏱ これはデモアカウントです。{n}時間後に自動的に削除されます。"
  },
  "pl": {
    "name": "Polski",
    "subtitle": "panel webowy",
    "username": "Nazwa użytkownika",
    "username_ph": "4–8 znaków, a-z 0-9",
    "email": "Adres e-mail",
    "email_ph": "uzytkownik@przyklad.pl",
    "domain": "Domena",
    "domain_ph": "przyklad.pl",
    "password": "Hasło",
    "password_ph": "Min. 8 znaków",
    "confirm": "Potwierdź hasło",
    "confirm_ph": "Powtórz",
    "register": "Zarejestruj się",
    "already_registered": "Masz już konto?",
    "to_login": "Do logowania",
    "to_panel": "Przejdź do panelu",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Słabe",
    "pw_medium": "Średnie",
    "pw_strong": "Silne",
    "please_wait": "Proszę czekać...",
    "success_heading": "Konto zostało utworzone!",
    "generate": "Generuj",
    "maintenance_heading": "Tryb konserwacji",
    "maintenance_text": "Rejestracja nowych kont została tymczasowo wstrzymana z powodu prac konserwacyjnych. Spróbuj ponownie później.",
    "tos_prefix": "Akceptuję",
    "tos_link": "Regulamin serwisu",
    "tos_and": "oraz",
    "privacy_link": "Politykę prywatności",
    "did_you_mean": "Czy miałeś na myśli",
    "setup_2fa": "Zalecamy włączenie uwierzytelniania dwuskładnikowego (2FA) w panelu.",
    "copy_pw": "Kopiuj",
    "need_help": "Potrzebujesz pomocy?",
    "contact_support": "Skontaktuj się z pomocą",
    "forgot_password": "Nie pamiętasz hasła?",
    "pw_req_length": "Co najmniej {n} znaków",
    "pw_req_upper": "Jedna wielka litera (A-Z)",
    "pw_req_lower": "Jedna mała litera (a-z)",
    "pw_req_number": "Jedna cyfra (0-9)",
    "email_mx_invalid": "Domena e-mail nie wydaje się przyjmować poczty.",
    "pw_hibp_warning": "⚠️ To hasło wyciekło w {n} wyciekach danych.",
    "pw_hibp_ok": "✓ Hasła nie znaleziono w znanych wyciekach danych.",
    "pw_hibp_checking": "Sprawdzanie bezpieczeństwa hasła...",
    "invite_code": "Kod zaproszenia",
    "invite_code_ph": "Wprowadź kod zaproszenia",
    "invite_required": "Do rejestracji wymagany jest kod zaproszenia.",
    "invite_invalid": "Nieprawidłowy lub wykorzystany kod zaproszenia.",
    "demo_notice": "⏱ To jest konto demonstracyjne i zostanie automatycznie usunięte po {n} godz."
  },
  "pt": {
    "name": "Português",
    "subtitle": "painel de controlo web",
    "username": "Nome de Utilizador",
    "username_ph": "4–8 caract., a-z 0-9",
    "email": "Endereço de E-mail",
    "email_ph": "utilizador@exemplo.pt",
    "domain": "Domínio",
    "domain_ph": "exemplo.pt",
    "password": "Palavra-passe",
    "password_ph": "Mín. 8 caract.",
    "confirm": "Confirmar Palavra-passe",
    "confirm_ph": "Repetir",
    "register": "Registar",
    "already_registered": "Já registado?",
    "to_login": "Ir para o Login",
    "to_panel": "Ir para o Painel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Fraca",
    "pw_medium": "Média",
    "pw_strong": "Forte",
    "please_wait": "Aguarde...",
    "success_heading": "Conta Criada!",
    "generate": "Gerar",
    "maintenance_heading": "Modo de Manutenção",
    "maintenance_text": "Novos registos estão temporariamente suspensos para manutenção. Tente novamente mais tarde.",
    "tos_prefix": "Concordo com os",
    "tos_link": "Termos de Serviço",
    "tos_and": "e a",
    "privacy_link": "Política de Privacidade",
    "did_you_mean": "Queria dizer",
    "setup_2fa": "Recomendamos ativar a Autenticação de Dois Fatores (2FA) no painel.",
    "copy_pw": "Copiar",
    "need_help": "Precisa de Ajuda?",
    "contact_support": "Contactar Suporte",
    "forgot_password": "Esqueceu-se da Palavra-passe?",
    "pw_req_length": "Pelo menos {n} caracteres",
    "pw_req_upper": "Uma letra maiúscula (A-Z)",
    "pw_req_lower": "Uma letra minúscula (a-z)",
    "pw_req_number": "Um número (0-9)",
    "email_mx_invalid": "O domínio do e-mail parece não aceitar mensagens.",
    "pw_hibp_warning": "⚠️ Esta palavra-passe apareceu em {n} violações de dados.",
    "pw_hibp_ok": "✓ Palavra-passe não encontrada em violações de dados conhecidas.",
    "pw_hibp_checking": "A verificar segurança da palavra-passe...",
    "invite_code": "Código de Convite",
    "invite_code_ph": "Insira o seu código de convite",
    "invite_required": "Um código de convite é necessário para registar.",
    "invite_invalid": "Código de convite inválido ou já utilizado.",
    "demo_notice": "⏱ Esta é uma conta de demonstração e será eliminada automaticamente após {n} hora(s)."
  },
  "ro": {
    "name": "Română",
    "subtitle": "panou de control web",
    "username": "Nume de utilizator",
    "username_ph": "4–8 caractere, a-z 0-9",
    "email": "Adresă de e-mail",
    "email_ph": "utilizator@exemplu.ro",
    "domain": "Domeniu",
    "domain_ph": "exemplu.ro",
    "password": "Parolă",
    "password_ph": "Min. 8 caractere",
    "confirm": "Confirmă parola",
    "confirm_ph": "Repetă",
    "register": "Înregistrare",
    "already_registered": "Ai deja un cont?",
    "to_login": "La autentificare",
    "to_panel": "Merg la panou",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Slabă",
    "pw_medium": "Medie",
    "pw_strong": "Puternică",
    "please_wait": "Vă rugăm așteptați...",
    "success_heading": "Cont creat cu succes!",
    "generate": "Generează",
    "maintenance_heading": "Mod de întreținere",
    "maintenance_text": "Înregistrările noi sunt întrerupte temporar pentru întreținere. Vă rugăm să încercați mai târziu.",
    "tos_prefix": "Sunt de acord cu",
    "tos_link": "Termenii și Condițiile",
    "tos_and": "și",
    "privacy_link": "Politica de Confidențialitate",
    "did_you_mean": "Ați vrut să spuneți",
    "setup_2fa": "Vă recomandăm să activați Autentificarea cu doi factori (2FA) în panou.",
    "copy_pw": "Copiază",
    "need_help": "Ai nevoie de ajutor?",
    "contact_support": "Contactează Suportul",
    "forgot_password": "Ai uitat parola?",
    "pw_req_length": "Cel puțin {n} caractere",
    "pw_req_upper": "O literă mare (A-Z)",
    "pw_req_lower": "O literă mică (a-z)",
    "pw_req_number": "Un număr (0-9)",
    "email_mx_invalid": "Domeniul de e-mail nu pare să accepte mesaje.",
    "pw_hibp_warning": "⚠️ Această parolă a apărut în {n} scurgeri de date.",
    "pw_hibp_ok": "✓ Parola nu a fost găsită în scurgeri cunoscute de date.",
    "pw_hibp_checking": "Se verifică securitatea parolei...",
    "invite_code": "Cod de invitație",
    "invite_code_ph": "Introduceți codul de invitație",
    "invite_required": "Este necesar un cod de invitație pentru înregistrare.",
    "invite_invalid": "Cod de invitație nevalid sau deja utilizat.",
    "demo_notice": "⏱ Acesta este un cont demo și va fi șters automat după {n} oră/ore."
  },
  "ru": {
    "name": "Русский",
    "subtitle": "веб-панель управления",
    "username": "Имя пользователя",
    "username_ph": "4–8 симв., a-z 0-9",
    "email": "Адрес электронной почты",
    "email_ph": "user@example.com",
    "domain": "Домен",
    "domain_ph": "example.com",
    "password": "Пароль",
    "password_ph": "Мин. 8 симв.",
    "confirm": "Подтверждение",
    "confirm_ph": "Повторите",
    "register": "Зарегистрироваться",
    "already_registered": "Уже зарегистрированы?",
    "to_login": "К входу",
    "to_panel": "В панель",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Слабый",
    "pw_medium": "Средний",
    "pw_strong": "Надежный",
    "please_wait": "Пожалуйста, подождите...",
    "success_heading": "Аккаунт успешно создан!",
    "generate": "Сгенерировать",
    "maintenance_heading": "Режим обслуживания",
    "maintenance_text": "Регистрация новых аккаунтов временно приостановлена. Попробуйте позже.",
    "tos_prefix": "Я согласен с",
    "tos_link": "Условиями использования",
    "tos_and": "и",
    "privacy_link": "Политикой конфиденциальности",
    "did_you_mean": "Возможно, вы имели в виду",
    "setup_2fa": "Рекомендуем включить двухфакторную аутентификацию (2FA) в панели.",
    "copy_pw": "Копировать",
    "need_help": "Нужна помощь?",
    "contact_support": "Связаться с поддержкой",
    "forgot_password": "Забыли пароль?",
    "pw_req_length": "Не менее {n} символов",
    "pw_req_upper": "Заглавная буква (A-Z)",
    "pw_req_lower": "Строчная буква (a-z)",
    "pw_req_number": "Цифра (0-9)",
    "email_mx_invalid": "Домен электронной почты не принимает письма.",
    "pw_hibp_warning": "⚠️ Этот пароль обнаружен в {n} утечках данных.",
    "pw_hibp_ok": "✓ Пароль не найден в известных утечках данных.",
    "pw_hibp_checking": "Проверка безопасности пароля...",
    "invite_code": "Код приглашения",
    "invite_code_ph": "Введите код приглашения",
    "invite_required": "Для регистрации требуется код приглашения.",
    "invite_invalid": "Недействительный или уже использованный код.",
    "demo_notice": "⏱ Это демо-аккаунт, он будет автоматически удален через {n} час(а/ов)."
  },
  "es": {
    "name": "Español",
    "subtitle": "panel de control web",
    "username": "Nombre de usuario",
    "username_ph": "4–8 caract., a-z 0-9",
    "email": "Correo electrónico",
    "email_ph": "usuario@ejemplo.com",
    "domain": "Dominio",
    "domain_ph": "ejemplo.com",
    "password": "Contraseña",
    "password_ph": "Mín. 8 caract.",
    "confirm": "Confirmar contraseña",
    "confirm_ph": "Repetir",
    "register": "Registrarse",
    "already_registered": "¿Ya tienes una cuenta?",
    "to_login": "Ir a Iniciar Sesión",
    "to_panel": "Ir al Panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Débil",
    "pw_medium": "Media",
    "pw_strong": "Fuerte",
    "please_wait": "Por favor espere...",
    "success_heading": "¡Cuenta Creada!",
    "generate": "Generar",
    "maintenance_heading": "Modo de Mantenimiento",
    "maintenance_text": "Los nuevos registros están suspendidos temporalmente por mantenimiento. Por favor, intente más tarde.",
    "tos_prefix": "Acepto los",
    "tos_link": "Términos del Servicio",
    "tos_and": "y la",
    "privacy_link": "Política de Privacidad",
    "did_you_mean": "¿Quiso decir",
    "setup_2fa": "Recomendamos activar la Autenticación de Dos Factores (2FA) en el panel.",
    "copy_pw": "Copiar",
    "need_help": "¿Necesita ayuda?",
    "contact_support": "Contactar Soporte",
    "forgot_password": "¿Olvidó su contraseña?",
    "pw_req_length": "Al menos {n} caracteres",
    "pw_req_upper": "Una letra mayúscula (A-Z)",
    "pw_req_lower": "Una letra minúscula (a-z)",
    "pw_req_number": "Un número (0-9)",
    "email_mx_invalid": "El dominio del correo no parece recibir mensajes.",
    "pw_hibp_warning": "⚠️ Esta contraseña apareció en {n} filtraciones de datos.",
    "pw_hibp_ok": "✓ La contraseña no se encontró en filtraciones conocidas.",
    "pw_hibp_checking": "Comprobando la seguridad de la contraseña...",
    "invite_code": "Código de Invitación",
    "invite_code_ph": "Ingrese su código de invitación",
    "invite_required": "Se requiere un código de invitación para registrarse.",
    "invite_invalid": "Código de invitación no válido o ya utilizado.",
    "demo_notice": "⏱ Esta es una cuenta de demostración y se eliminará automáticamente tras {n} hora(s)."
  },
  "sv": {
    "name": "Svenska",
    "subtitle": "webbkontrollpanel",
    "username": "Användarnamn",
    "username_ph": "4–8 tecken, a-z 0-9",
    "email": "E-postadress",
    "email_ph": "anvandare@exempel.se",
    "domain": "Domän",
    "domain_ph": "exempel.se",
    "password": "Lösenord",
    "password_ph": "Minst 8 tecken",
    "confirm": "Bekräfta lösenord",
    "confirm_ph": "Upprepa",
    "register": "Registrera",
    "already_registered": "Redan registrerad?",
    "to_login": "Till inloggning",
    "to_panel": "Gå till panelen",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Svagt",
    "pw_medium": "Medel",
    "pw_strong": "Starkt",
    "please_wait": "Vänligen vänta...",
    "success_heading": "Konto skapat!",
    "generate": "Generera",
    "maintenance_heading": "Underhållsläge",
    "maintenance_text": "Nya registreringar är tillfälligt stoppade för underhåll. Vänligen återkom senare.",
    "tos_prefix": "Jag godkänner",
    "tos_link": "Användarvillkoren",
    "tos_and": "och",
    "privacy_link": "Integritetspolicyn",
    "did_you_mean": "Menade du",
    "setup_2fa": "Vi rekommenderar att aktivera tvåfaktorsautentisering (2FA) i panelen.",
    "copy_pw": "Kopiera",
    "need_help": "Behöver du hjälp?",
    "contact_support": "Kontakta support",
    "forgot_password": "Glömt lösenordet?",
    "pw_req_length": "Minst {n} tecken",
    "pw_req_upper": "En stor bokstav (A-Z)",
    "pw_req_lower": "En liten bokstav (a-z)",
    "pw_req_number": "Ett nummer (0-9)",
    "email_mx_invalid": "E-postdomänen verkar inte ta emot e-post.",
    "pw_hibp_warning": "⚠️ Detta lösenord har förekommit i {n} dataläckor.",
    "pw_hibp_ok": "✓ Lösenordet hittades inte i kända dataläckor.",
    "pw_hibp_checking": "Kontrollerar lösenordssäkerhet...",
    "invite_code": "Inbjudningskod",
    "invite_code_ph": "Ange din inbjudningskod",
    "invite_required": "En inbjudningskod krävs för att registrera sig.",
    "invite_invalid": "Ogiltig eller redan använd inbjudningskod.",
    "demo_notice": "⏱ Detta är ett demokonto och raderas automatiskt efter {n} timme/timmar."
  },
  "sk": {
    "name": "Slovenčina",
    "subtitle": "webový ovládací panel",
    "username": "Používateľské meno",
    "username_ph": "4–8 znakov, a-z 0-9",
    "email": "E-mailová adresa",
    "email_ph": "pouzivatel@priklad.sk",
    "domain": "Doména",
    "domain_ph": "priklad.sk",
    "password": "Heslo",
    "password_ph": "Min. 8 znakov",
    "confirm": "Potvrdenie hesla",
    "confirm_ph": "Opakovať",
    "register": "Registrovať sa",
    "already_registered": "Už máte účet?",
    "to_login": "Na prihlásenie",
    "to_panel": "Prejsť do panelu",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Slabé",
    "pw_medium": "Stredné",
    "pw_strong": "Silné",
    "please_wait": "Prosím čakajte...",
    "success_heading": "Účet bol vytvorený!",
    "generate": "Generovať",
    "maintenance_heading": "Režim údržby",
    "maintenance_text": "Nové registrácie sú z dôvodu údržby dočasne pozastavené. Skúste to znova neskôr.",
    "tos_prefix": "Súhlasím s",
    "tos_link": "Podmienkami služby",
    "tos_and": "a",
    "privacy_link": "Zásadami ochrany osobných údajov",
    "did_you_mean": "Mali ste na mysli",
    "setup_2fa": "Odporúčame aktivovať dvojfázové overenie (2FA) v ovládacom paneli.",
    "copy_pw": "Kopírovať",
    "need_help": "Potrebujete pomoc?",
    "contact_support": "Kontaktovať podporu",
    "forgot_password": "Zabudli ste heslo?",
    "pw_req_length": "Alespoň {n} znakov",
    "pw_req_upper": "Jedno veľké písmeno (A-Z)",
    "pw_req_lower": "Jedno malé písmeno (a-z)",
    "pw_req_number": "Jedno číslo (0-9)",
    "email_mx_invalid": "E-mailová doména neuskladňuje ani neprijíma poštu.",
    "pw_hibp_warning": "⚠️ Toto heslo sa objavilo v {n} únikoch údajov.",
    "pw_hibp_ok": "✓ Heslo sa nenašlo v známych únikoch údajov.",
    "pw_hibp_checking": "Kontrola bezpečnosti hesla...",
    "invite_code": "Pozvánkový kód",
    "invite_code_ph": "Zadajte váš pozvánkový kód",
    "invite_required": "Na registráciu sa vyžaduje pozvánkový kód.",
    "invite_invalid": "Neplatný alebo už použitý pozvánkový kód.",
    "demo_notice": "⏱ Toto je demo účet a bude automaticky vymazaný po {n} hodine/hodinách."
  },
  "tr": {
    "name": "Türkçe",
    "subtitle": "web kontrol paneli",
    "username": "Kullanıcı Adı",
    "username_ph": "4–8 karakter, a-z 0-9",
    "email": "E-posta Adresi",
    "email_ph": "kullanici@ornek.com",
    "domain": "Alan Adı (Domain)",
    "domain_ph": "ornek.com",
    "password": "Parola",
    "password_ph": "Min. 8 karakter",
    "confirm": "Parolayı Onayla",
    "confirm_ph": "Tekrar yazın",
    "register": "Kayıt Ol",
    "already_registered": "Zaten hesabınız var mı?",
    "to_login": "Giriş Yap",
    "to_panel": "Panele Git",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Zayıf",
    "pw_medium": "Orta",
    "pw_strong": "Güçlü",
    "please_wait": "Lütfen bekleyin...",
    "success_heading": "Hesap Oluşturuldu!",
    "generate": "Otomatik Üret",
    "maintenance_heading": "Bakım Modu",
    "maintenance_text": "Bakım çalışmaları nedeniyle yeni kayıtlar geçici olarak durdurulmuştur. Lütfen daha sonra tekrar deneyin.",
    "tos_prefix": "Kabul ediyorum:",
    "tos_link": "Hizmet Şartları",
    "tos_and": "ve",
    "privacy_link": "Gizlilik Politikası",
    "did_you_mean": "Bunu mu demek istediniz:",
    "setup_2fa": "Panelden İki Faktörlü Doğrulamayı (2FA) etkinleştirmenizi öneririz.",
    "copy_pw": "Kopyala",
    "need_help": "Yardım mı lazım?",
    "contact_support": "Destek ile İletişime Geç",
    "forgot_password": "Parolanızı mı unuttunuz?",
    "pw_req_length": "En az {n} karakter",
    "pw_req_upper": "Bir büyük harf (A-Z)",
    "pw_req_lower": "Bir küçük harf (a-z)",
    "pw_req_number": "Bir rakam (0-9)",
    "email_mx_invalid": "E-posta alan adı e-posta kabul etmiyor gibi görünüyor.",
    "pw_hibp_warning": "⚠️ Bu parola {n} veri ihlalinde göründü.",
    "pw_hibp_ok": "✓ Parola bilinen veri ihlallerinde bulunamadı.",
    "pw_hibp_checking": "Parola güvenliği kontrol ediliyor...",
    "invite_code": "Davet Kodu",
    "invite_code_ph": "Davet kodunuzu girin",
    "invite_required": "Kayıt olmak için davet kodu gereklidir.",
    "invite_invalid": "Geçersiz veya kullanılmış davet kodu.",
    "demo_notice": "⏱ Bu bir demo hesabıdır ve {n} saat sonra otomatik olarak silinecektir."
  }
};
  </script>
</head>

<body>

  <!-- Preloader -->
  <div id="preloader">
    <div id="preloader-spinner">
      <div></div>
      <div></div>
      <div></div>
    </div>
  </div>

  <!-- Polygon Background -->
  <div class="bg-poly" aria-hidden="true">
    <svg viewBox="0 0 1440 900" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
      <defs>
        <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1a2744" />
          <stop offset="100%" stop-color="#0a0f1e" />
        </linearGradient>
      </defs>
      <polygon points="0,0 480,0 240,300" fill="#1a2744" opacity=".6" />
      <polygon points="480,0 960,0 720,240" fill="#162038" opacity=".5" />
      <polygon points="960,0 1440,0 1200,200" fill="#0d1525" opacity=".7" />
      <polygon points="0,300 240,300 0,600" fill="#111a2e" opacity=".5" />
      <polygon points="240,300 600,150 480,450" fill="#1c2940" opacity=".4" />
      <polygon points="600,150 960,0 720,240" fill="#162038" opacity=".4" />
      <polygon points="1200,200 1440,0 1440,400" fill="#0e1826" opacity=".6" />
      <polygon points="0,600 0,900 300,900" fill="#141f33" opacity=".5" />
      <polygon points="300,900 600,700 900,900" fill="#0d1828" opacity=".4" />
      <polygon points="900,900 1440,700 1440,900" fill="#111c30" opacity=".6" />
      <polygon points="600,700 900,500 1200,700" fill="#172240" opacity=".35" />
      <polygon points="0,600 300,900 600,700 480,450" fill="#0f1a2e" opacity=".3" />
      <polygon points="1200,200 1440,400 1200,700 900,500" fill="#0c1622" opacity=".4" />
    </svg>
  </div>

  <!-- Theme Toggle & Language Selector -->
  <div class="top-controls" role="toolbar" aria-label="Settings">
    <button class="icon-btn" id="themeToggle" aria-label="Toggle theme" title="Light/Dark Mode">
      <!-- Sun icon (light) -->
      <svg id="iconSun" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
        stroke-width="2" style="display:none">
        <circle cx="12" cy="12" r="4" />
        <path
          d="M12 2v2m0 16v2M4.22 4.22l1.42 1.42m12.72 12.72 1.42 1.42M2 12h2m16 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
      </svg>
      <!-- Moon icon (dark) -->
      <svg id="iconMoon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
        stroke-width="2">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
      </svg>
    </button>

    <div class="lang-dropdown-wrap" id="langWrap">
      <button type="button" class="lang-btn" id="langBtn" aria-label="Select language" aria-expanded="false">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" />
          <path
            d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        <span id="currentLangLabel">English</span>
      </button>
      <div class="lang-dropdown" id="langDropdown" role="menu"></div>
    </div>
  </div>

  <!-- Card -->
  <div class="card">
    <!-- Header with ISPConfig Logo -->
    <div class="card-header">
      <svg class="logo-icon" viewBox="0 0 54 42" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="2" y="2" width="50" height="32" rx="4" stroke="#cc0000" stroke-width="3.5" fill="none"/>
        <line x1="16" y1="39" x2="38" y2="39" stroke="#cc0000" stroke-width="3.5" stroke-linecap="round"/>
        <line x1="27" y1="34" x2="27" y2="39" stroke="#cc0000" stroke-width="3.5"/>
        <rect x="10" y="21" width="6" height="6" fill="#cc0000"/>
        <path d="M 10 13 L 24 13 L 24 25" stroke="#cc0000" stroke-width="3.5" stroke-linecap="square" fill="none"/>
      </svg>
      <div class="logo-text">
        <h1><span class="isp-red">ISP</span><span class="config-dark">CONFIG</span></h1>
      </div>
    </div>

    <!-- Body -->
    <div class="card-body">
    <?php if (MAINTENANCE_MODE): ?>
      <div style="text-align:center; padding: 40px 10px 20px;">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--sub)" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px; display:inline-block;">
          <path
            d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z">
          </path>
        </svg>
        <h2 style="margin-bottom:12px; font-weight:600; font-size:1.5rem; color:var(--text);"
          data-i18n="maintenance_heading">Maintenance Mode</h2>
        <p style="color:var(--sub); margin-bottom:20px; font-size: 1rem; line-height:1.5;" data-i18n="maintenance_text">
          New registrations are currently paused for maintenance. Please check back later.
        </p>
      </div>
    <?php elseif ($result && $result['success']): ?>
      <div style="text-align:center; padding: 24px 10px 10px; animation: fadeIn 0.4s ease-out;">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--ok-text)" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:16px; display:inline-block;">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
          <polyline points="22 4 12 14.01 9 11.01"></polyline>
        </svg>
        <h2 style="margin-bottom:10px; font-weight:600; font-size:1.5rem; color:var(--text);" data-i18n="success_heading">
          Account Created!</h2>
        <p style="color:var(--sub); margin-bottom:16px; font-size: 0.92rem; line-height:1.5;">
          <?= htmlspecialchars($result['message']) ?>
        </p>
        <div
          style="background: var(--ok-bg); border: 1px solid var(--ok-b); border-radius: 4px; padding: 12px 16px; margin-bottom: <?= (defined('DEMO_MODE') && DEMO_MODE) ? '12' : '20' ?>px;">
          <p style="color: var(--ok-text); font-size: 0.85rem; margin: 0; line-height: 1.4;" data-i18n="setup_2fa">
            We recommend enabling Two-Factor Authentication (2FA) in the panel.
          </p>
        </div>
        <?php if (defined('DEMO_MODE') && DEMO_MODE): ?>
        <p style="background:var(--err-bg); border:1px solid var(--err-b); border-radius:4px; padding:12px 16px; margin-bottom:20px; font-size:0.85rem; line-height:1.5; color:var(--err-text);"
          data-i18n-demo-hours="<?= (int)(defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?>"
          data-i18n="demo_notice">
          ⏱ This is a demo account and will be automatically deleted after <?= (int)(defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?> hour(s).
        </p>
        <?php endif; ?>
        <a href="<?= htmlspecialchars(PANEL_URL) ?>" class="btn"
          style="text-decoration:none; display:inline-flex; width:auto; padding:8px 24px;" data-i18n="to_login">To Login</a>
      </div>
    <?php else: ?>
      <?php if ($result && !$result['success']): ?>
        <div class="alert alert-error">
          <?= htmlspecialchars($result['message']) ?>
        </div>
      <?php endif; ?>

      <form method="POST" action="" id="regForm" novalidate autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>" />
        <input type="text" name="website_hp" style="display:none" tabindex="-1" autocomplete="off">

        <div class="field">
          <label for="username" data-i18n="username">Username</label>
          <input type="text" id="username" name="username" data-i18n-ph="username_ph" placeholder="4–8 chars, a-z 0-9"
            value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" maxlength="8" autocomplete="username" required>
        </div>

        <div class="field">
          <label for="email" data-i18n="email">Email Address</label>
          <input type="email" id="email" name="email" data-i18n-ph="email_ph" placeholder="user@example.com"
            value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" autocomplete="email" required>
          <div id="emailSuggestion" style="display:none; font-size: 0.85rem; margin-top: 6px; color: var(--sub);">
            <span data-i18n="did_you_mean">Did you mean</span> <a href="#" id="emailSuggestionLink"
              style="color: #cc0000; text-decoration: none; font-weight: 500;"></a>?
          </div>
        </div>

        <div class="field">
          <label for="domain" data-i18n="domain">Domain</label>
          <input type="text" id="domain" name="domain" data-i18n-ph="domain_ph" placeholder="example.com"
            value="<?= htmlspecialchars($_POST['domain'] ?? '') ?>" autocomplete="off" required>
        </div>

        <div class="field-row">
          <div class="field" style="margin-bottom:0">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <label for="passwd" data-i18n="password" style="margin-bottom:0;">Password</label>
              <button type="button" id="generatePwBtn"
                style="background:none; border:none; cursor:pointer; color:#cc0000; font-size:0.75rem; display:flex; align-items:center; gap:4px; padding:0;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round">
                  <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                </svg>
                <span data-i18n="generate">Generate</span>
              </button>
            </div>
            <div class="input-wrap">
              <input type="password" id="passwd" name="passwd" class="pw-field" data-i18n-ph="password_ph"
                placeholder="Min. <?= PASSWD_MIN_LENGTH ?> chars" autocomplete="new-password" required>
              <button type="button" class="eye-btn" data-target="passwd" aria-label="Show password">
                <!-- Eye open (default: password hidden) -->
                <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <!-- Eye closed (shown when password is visible) -->
                <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field" style="margin-bottom:0">
            <label for="passwd2" data-i18n="confirm">Confirm</label>
            <div class="input-wrap">
              <input type="password" id="passwd2" name="passwd2" class="pw-field" data-i18n-ph="confirm_ph"
                placeholder="Repeat" autocomplete="new-password" required>
              <button type="button" class="eye-btn" data-target="passwd2" aria-label="Show password">
                <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        <div class="pw-meter" id="pwMeter">
          <div class="pw-meter-bar">
            <div class="pw-meter-fill" id="pwMeterFill"></div>
          </div>
          <div class="pw-meter-text">
            <span id="pwHint" data-i18n="pw_hint">A-Z, a-z, 0-9</span>
            <div style="display:flex; align-items:center; gap:10px;">
              <span id="pwMeterText"></span>
              <button type="button" id="copyPwBtn" class="copy-pw-btn" style="display:none;" title="Copy password">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                <span id="copyPwLabel" data-i18n="copy_pw">Copy</span>
              </button>
            </div>
          </div>
        </div>

        <?php if (defined('PASSWD_SHOW_CHECKLIST') && PASSWD_SHOW_CHECKLIST): ?>
        <ul class="pw-checklist" id="pwChecklist"
            data-min="<?= PASSWD_MIN_LENGTH ?>"
            data-complexity="<?= PASSWD_REQUIRE_COMPLEXITY ? '1' : '0' ?>">
          <li class="pw-check-item" id="chk-length">
            <span class="check-icon">✓</span>
            <span data-i18n-min="pw_req_length">At least <?= PASSWD_MIN_LENGTH ?> characters</span>
          </li>
          <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          <li class="pw-check-item" id="chk-upper">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_upper">One uppercase letter (A-Z)</span>
          </li>
          <li class="pw-check-item" id="chk-lower">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_lower">One lowercase letter (a-z)</span>
          </li>
          <li class="pw-check-item" id="chk-number">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_number">One number (0-9)</span>
          </li>
          <?php endif; ?>
        </ul>
        <?php endif; ?>

        <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
        <div class="hibp-status" id="hibpStatus"></div>
        <?php endif; ?>

        <?php if (defined('INVITE_ONLY_MODE') && INVITE_ONLY_MODE): ?>
          <div class="field">
            <label for="invite_code" data-i18n="invite_code">Invitation Code</label>
            <input type="text" id="invite_code" name="invite_code"
                   data-i18n-ph="invite_code_ph" placeholder="Enter your invite code"
                   maxlength="32" autocomplete="off" spellcheck="false"
                   style="text-transform:uppercase; letter-spacing:0.05em;">
          </div>
        <?php endif; ?>

        <?php if (!empty(TOS_URL) || !empty(PRIVACY_URL)): ?>
          <div class="field" style="margin-top: 15px; display: flex; align-items: flex-start; gap: 8px;">
            <input type="checkbox" id="tos_agree" name="tos_agree" value="1" required
              style="margin-top: 3px; cursor: pointer; width: auto;">
            <label for="tos_agree"
              style="font-size: 0.85rem; color: var(--sub); line-height: 1.4; font-weight: normal; cursor: pointer;">
              <span data-i18n="tos_prefix">I agree to the</span>
              <?php if (!empty(TOS_URL)): ?>
                <a href="<?= htmlspecialchars(TOS_URL) ?>" target="_blank" data-i18n="tos_link"
                  style="color: #cc0000; text-decoration: underline;">Terms of Service</a>
              <?php endif; ?>
              <?php if (!empty(TOS_URL) && !empty(PRIVACY_URL)): ?>
                <span data-i18n="tos_and">and</span>
              <?php endif; ?>
              <?php if (!empty(PRIVACY_URL)): ?>
                <a href="<?= htmlspecialchars(PRIVACY_URL) ?>" target="_blank" data-i18n="privacy_link"
                  style="color: #cc0000; text-decoration: underline;">Privacy Policy</a>
              <?php endif; ?>
            </label>
          </div>
        <?php endif; ?>

        <div class="captcha-wrapper" style="margin-top: 18px; display: flex; justify-content: center; width: 100%;">
          <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
            <div class="h-captcha" data-sitekey="<?= htmlspecialchars(HCAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
            <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars(RECAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
            <altcha-widget challengeurl="altcha-challenge.php"></altcha-widget>
          <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
            <div class="cf-turnstile" data-sitekey="<?= htmlspecialchars(TURNSTILE_SITE_KEY) ?>"
              <?= $rateLimited ? 'data-execution="execute"' : '' ?>></div>
          <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
            <div class="mtcaptcha"></div>
          <?php endif; ?>
        </div>

        <div class="btn-wrap">
          <button type="submit" class="btn" id="submitBtn" <?= $rateLimited ? 'disabled' : '' ?>>
            <div class="spinner" id="spinner"></div>
            <span id="submitLabel" data-i18n="register">Register</span>
          </button>
        </div>
      </form>

      <p class="login-link">
        <span data-i18n="already_registered">Already registered?</span> <a href="<?= htmlspecialchars(PANEL_URL) ?>"
          target="_blank" data-i18n="to_login">To Login</a>
      </p>
    <?php endif; ?>
    </div>
  </div>

  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
  <!-- Cookie Consent Banner -->
  <div id="cookieBanner" role="dialog" aria-label="Cookie consent" aria-live="polite">
    <p id="cookieBannerText"><?= htmlspecialchars(COOKIE_BANNER_TEXT) ?></p>
    <button id="cookieAcceptBtn" type="button"><?= htmlspecialchars(COOKIE_BANNER_BTN) ?></button>
  </div>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
  <!-- Accessibility Widget -->
  <div id="a11yWidget" role="complementary" aria-label="Accessibility tools">
    <div id="a11yPanel" role="region" aria-label="Accessibility options">
      <h4>Accessibility</h4>
      <div class="a11y-row">
        <span class="a11y-label">Font Size</span>
        <div class="a11y-controls">
          <button class="a11y-btn" id="a11yFontDec" aria-label="Decrease font size" title="Decrease font size">A−</button>
          <span id="a11yFontSize">100%</span>
          <button class="a11y-btn" id="a11yFontInc" aria-label="Increase font size" title="Increase font size">A+</button>
        </div>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">High Contrast</span>
        <label class="a11y-toggle-switch" aria-label="Toggle high contrast">
          <input type="checkbox" id="a11yContrast">
          <span class="a11y-slider"></span>
        </label>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">Grayscale</span>
        <label class="a11y-toggle-switch" aria-label="Toggle grayscale">
          <input type="checkbox" id="a11yGrayscale">
          <span class="a11y-slider"></span>
        </label>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">Reduce Motion</span>
        <label class="a11y-toggle-switch" aria-label="Toggle reduce motion">
          <input type="checkbox" id="a11yMotion">
          <span class="a11y-slider"></span>
        </label>
      </div>
    </div>
    <button id="a11yToggleBtn" aria-label="Open accessibility tools" aria-expanded="false" aria-controls="a11yPanel">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <path d="M12 8v4l2 2"/>
        <circle cx="12" cy="7" r="1" fill="currentColor" stroke="none"/>
        <path d="M9 17l1.5-4.5M15 17l-1.5-4.5M9 12.5h6"/>
      </svg>
    </button>
  </div>
  <?php endif; ?>

  <?php if (!empty(SUPPORT_EMAIL) || !empty(SUPPORT_URL)): ?>
    <div class="help-fab-wrap" id="helpFabWrap">
      <button class="help-fab" type="button" id="helpFabBtn">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <span data-i18n="need_help">Need help?</span>
      </button>
      <div class="help-menu" id="helpMenu">
        <a href="<?= !empty(SUPPORT_URL) ? htmlspecialchars(SUPPORT_URL) : 'mailto:' . htmlspecialchars(SUPPORT_EMAIL) ?>"
          target="_blank" data-i18n="contact_support">Contact Support</a>
        <a href="<?php
            $resetMail = !empty(SUPPORT_RESET_EMAIL) ? SUPPORT_RESET_EMAIL : SUPPORT_EMAIL;
            echo 'mailto:' . htmlspecialchars($resetMail)
                . '?subject=' . rawurlencode('Password Reset Request')
                . '&body=' . rawurlencode("Hello,\n\nI would like to request a password reset for my account.\n\nUsername: \nRegistered domain: \n\nThank you.");
          ?>" data-i18n="forgot_password">Forgot Password?</a>
      </div>
    </div>
  <?php endif; ?>

  <script>
    // ── Theme Toggle ──────────────────────────────────────────────────────────
    const html = document.documentElement;
    const themeBtn = document.getElementById('themeToggle');
    const iconSun = document.getElementById('iconSun');
    const iconMoon = document.getElementById('iconMoon');

    function applyTheme(t) {
      if (t === 'dark') {
        html.setAttribute('data-theme', 'dark');
      } else {
        html.removeAttribute('data-theme');
      }
      iconSun.style.display = (t === 'dark') ? 'block' : 'none';
      iconMoon.style.display = (t !== 'dark') ? 'block' : 'none';
      localStorage.setItem('isp_theme', t);
    }
    let initTheme = localStorage.getItem('isp_theme') || 'light';
    applyTheme(initTheme);
    themeBtn.addEventListener('click', () => {
      applyTheme(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
    });

    // ── Password Strength Meter ───────────────────────────────────────────────
    const pwInput = document.getElementById('passwd');
    const pwMeterFill = document.getElementById('pwMeterFill');
    const pwMeterText = document.getElementById('pwMeterText');

    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const val = this.value;
        if (!val) {
          pwMeterFill.style.width = '0%';
          pwMeterText.textContent = '';
          return;
        }
        let score = 0;
        if (val.length >= <?= PASSWD_MIN_LENGTH ?>) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[a-z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        const langCode = localStorage.getItem('isp_lang') || 'en';
        const curDict = I18N[langCode] || I18N['en'];
        let width = '25%', color = '#ff4d4d', label = curDict.pw_weak || 'Weak';
        if (score >= 4) {
          width = '100%'; color = '#2ecc71'; label = curDict.pw_strong || 'Strong';
        } else if (score >= 3) {
          width = '66%'; color = '#ffa64d'; label = curDict.pw_medium || 'Medium';
        } else if (score >= 2) {
          width = '33%'; color = '#ff4d4d'; label = curDict.pw_weak || 'Weak';
        }

        pwMeterFill.style.width = width;
        pwMeterFill.style.backgroundColor = color;
        pwMeterText.textContent = label;
        pwMeterText.style.color = color;
      });
    }

    // ── Multi-Language (i18n) Engine ───────────────────────────────────────────

    const langDropdown = document.getElementById('langDropdown');
    const langBtn = document.getElementById('langBtn');

    // ── Password Generator ─────────────────────────────────────────────────────
    const generatePwBtn = document.getElementById('generatePwBtn');
    if (generatePwBtn) generatePwBtn.addEventListener('click', generatePassword);

    function generatePassword() {
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
      let pwd = "";
      pwd += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[Math.floor(Math.random() * 26)];
      pwd += "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)];
      pwd += "0123456789"[Math.floor(Math.random() * 10)];
      for (let i = 0; i < 9; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
      pwd = pwd.split('').sort(() => 0.5 - Math.random()).join('');

      const p1 = document.getElementById('passwd');
      const p2 = document.getElementById('passwd2');
      p1.value = pwd;
      p2.value = pwd;

      // Briefly show password so user can see what was generated
      p1.type = 'text'; p2.type = 'text';
      // Update eye button icons
      document.querySelectorAll('.eye-btn').forEach(btn => {
        btn.querySelector('.show-icon').style.display = 'none';
        btn.querySelector('.hide-icon').style.display = 'block';
      });
      p1.dispatchEvent(new Event('input'));

      // Show copy button
      const copyBtn = document.getElementById('copyPwBtn');
      if (copyBtn) copyBtn.style.display = 'flex';

      setTimeout(() => {
        p1.type = 'password'; p2.type = 'password';
        document.querySelectorAll('.eye-btn').forEach(btn => {
          btn.querySelector('.show-icon').style.display = 'block';
          btn.querySelector('.hide-icon').style.display = 'none';
        });
      }, 4000);
    }

    // ── Eye Toggle (Password Visibility) ──────────────────────────────────────
    document.querySelectorAll('.eye-btn').forEach(btn => {
      btn.addEventListener('click', function () {
        const targetId = this.dataset.target;
        const input = document.getElementById(targetId);
        if (!input) return;
        const isHidden = input.type === 'password';
        input.type = isHidden ? 'text' : 'password';
        this.querySelector('.show-icon').style.display = isHidden ? 'none' : 'block';
        this.querySelector('.hide-icon').style.display = isHidden ? 'block' : 'none';
      });
    });

    // ── Copy Password Button ───────────────────────────────────────────────────
    const copyPwBtn = document.getElementById('copyPwBtn');
    if (copyPwBtn) {
      copyPwBtn.addEventListener('click', function () {
        const pwEl = document.getElementById('passwd');
        const pw = pwEl ? pwEl.value : '';
        if (!pw) return;
        navigator.clipboard.writeText(pw).then(() => {
          this.classList.add('copied');
          const label = this.querySelector('#copyPwLabel');
          const origText = label.textContent;
          label.textContent = '✓';
          setTimeout(() => {
            this.classList.remove('copied');
            label.textContent = origText;
          }, 2000);
        });
      });
    }

    // Show copy button when user types password manually
    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const copyBtn = document.getElementById('copyPwBtn');
        if (copyBtn) copyBtn.style.display = this.value ? 'flex' : 'none';
      });
    }

    let currentLang = 'en';
    function setLanguage(langCode) {
      currentLang = langCode;
      document.documentElement.lang = langCode;
      const dict = I18N[langCode] || I18N['en'];
      localStorage.setItem('isp_lang', langCode);
      const langLabel = document.getElementById('currentLangLabel');
      if (langLabel) langLabel.textContent = dict.name;

      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (dict[key]) {
          let text = dict[key];
          if (key === 'demo_notice' && el.dataset.i18nDemoHours) {
            text = text.replace('{n}', el.dataset.i18nDemoHours);
          }
          el.textContent = text;
        }
      });

      document.querySelectorAll('[data-i18n-ph]').forEach(el => {
        const key = el.dataset.i18nPh;
        if (dict[key]) el.placeholder = dict[key];
      });

      document.querySelectorAll('[data-i18n-min]').forEach(el => {
        const key = el.dataset.i18nMin;
        const checklist = document.getElementById('pwChecklist');
        const minLen = checklist ? checklist.dataset.min : 8;
        if (dict[key]) el.textContent = dict[key].replace('{n}', minLen);
      });

      document.querySelectorAll('.lang-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === langCode);
      });
    }

    if (langDropdown && langBtn) {
      Object.keys(I18N).forEach(code => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'lang-item';
        item.dataset.lang = code;
        item.textContent = I18N[code].name;
        item.addEventListener('click', () => {
          setLanguage(code);
          langDropdown.classList.remove('show');
        });
        langDropdown.appendChild(item);
      });

      langBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        langDropdown.classList.toggle('show');
      });

      document.addEventListener('click', (e) => {
        const langWrap = document.getElementById('langWrap');
        if (langWrap && !langWrap.contains(e.target)) {
          langDropdown.classList.remove('show');
        }
      });

      // Init language from localStorage or browser settings
      const savedLang = localStorage.getItem('isp_lang') || navigator.language.slice(0, 2);
      setLanguage(I18N[savedLang] ? savedLang : 'en');
    }

    // ── Client-Side Validation & Submit Spinner ───────────────────────────────
    const regForm = document.getElementById('regForm');
    if (regForm) {
      regForm.addEventListener('submit', function (e) {
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const domain = document.getElementById('domain').value.trim();
        const pw = document.getElementById('passwd').value;
        const pw2 = document.getElementById('passwd2').value;

        if (!/^[a-z0-9]{4,8}$/i.test(username)) {
          e.preventDefault();
          alert('Username: 4–8 characters, only a-z and 0-9 allowed.');
          return;
        }
        if (!email.includes('@')) {
          e.preventDefault();
          alert('Please enter a valid email address.');
          return;
        }
        if (!domain.match(/^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$/i)) {
          e.preventDefault();
          alert('Please enter a valid domain (e.g. example.com).');
          return;
        }
        if (pw.length < <?= PASSWD_MIN_LENGTH ?>) {
          e.preventDefault();
          alert('Password must be at least <?= PASSWD_MIN_LENGTH ?> characters long.');
          return;
        }
        <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          if (!/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/[0-9]/.test(pw)) {
            e.preventDefault();
            alert('Password must contain at least one uppercase letter, one lowercase letter, and one number.');
            return;
          }
        <?php endif; ?>
        if (pw !== pw2) {
          e.preventDefault();
          alert('Passwords do not match.');
          return;
        }

        const btn = document.getElementById('submitBtn');
        const spinner = document.getElementById('spinner');
        const label = document.getElementById('submitLabel');
        if (spinner) spinner.style.display = 'block';
        const curLang = localStorage.getItem('isp_lang') || 'en';
        if (label) label.textContent = (I18N[curLang] || I18N['en']).please_wait || 'Please wait...';
        setTimeout(() => { if (btn) btn.disabled = true; }, 10);
      });
    }

    // ── Hide Preloader after page load ────────────────────────────────────────
    window.addEventListener('load', () => {
      const preloader = document.getElementById('preloader');
      if (preloader) {
        preloader.classList.add('hidden');
        // Remove from DOM after transition to free resources
        preloader.addEventListener('transitionend', () => preloader.remove(), { once: true });
      }
    });

    // ── Email Typo Detection ──────────────────────────────────────────────────
    const emailInput = document.getElementById('email');
    const emailSuggestion = document.getElementById('emailSuggestion');
    const emailSuggestionLink = document.getElementById('emailSuggestionLink');

    if (emailInput && emailSuggestion && emailSuggestionLink) {
      const commonDomains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
        'gmx.de', 'gmx.net', 'gmx.at', 'gmx.ch', 'web.de', 't-online.de', 'freenet.de', 'posteo.de', 'mailbox.org',
        'yandex.ru', 'mail.ru', 'inbox.ru', 'bk.ru', 'list.ru', 'rambler.ru',
        'proton.me', 'protonmail.com', 'tuta.com', 'tutamail.com',
        'live.com', 'msn.com', 'zoho.com'
      ];

      function calculateDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;
        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= b.length; i++) {
          for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
              matrix[i][j] = matrix[i - 1][j - 1];
            } else {
              matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
            }
          }
        }
        return matrix[b.length][a.length];
      }

      emailInput.addEventListener('blur', function () {
        const val = this.value.trim().toLowerCase();
        const parts = val.split('@');
        if (parts.length === 2 && parts[1].length > 0) {
          const user = parts[0];
          const domain = parts[1];
          let bestMatch = null;
          let minDistance = 3;

          if (commonDomains.includes(domain)) {
            emailSuggestion.style.display = 'none';
            return;
          }

          for (const cd of commonDomains) {
            const d = calculateDistance(domain, cd);
            if (d < minDistance) {
              minDistance = d;
              bestMatch = cd;
            }
          }

          if (bestMatch && bestMatch !== domain) {
            const suggestedEmail = user + '@' + bestMatch;
            emailSuggestionLink.textContent = suggestedEmail;
            emailSuggestion.style.display = 'block';

            emailSuggestionLink.onclick = function (e) {
              e.preventDefault();
              emailInput.value = suggestedEmail;
              emailSuggestion.style.display = 'none';
              emailInput.focus();
            };
          } else {
            emailSuggestion.style.display = 'none';
          }
        } else {
          emailSuggestion.style.display = 'none';
        }
      });
    }

    // Close help menu on outside click
    window.addEventListener('click', function (e) {
      const hm = document.getElementById('helpMenu');
      if (hm && hm.classList.contains('show') && !e.target.closest('#helpFabWrap')) {
        hm.classList.remove('show');
      }
    });

    // Help FAB toggle
    const helpFabBtn = document.getElementById('helpFabBtn');
    if (helpFabBtn) {
      helpFabBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        document.getElementById('helpMenu').classList.toggle('show');
      });
    }

    // ── Password Checklist ──────────────────────────────────────────────────
    (function() {
      const checklist = document.getElementById('pwChecklist');
      if (!checklist) return;

      const minLen     = parseInt(checklist.dataset.min, 10) || 8;
      const complexity = checklist.dataset.complexity === '1';
      const pwInput    = document.getElementById('passwd');
      if (!pwInput) return;

      const chkLength = document.getElementById('chk-length');
      const chkUpper  = document.getElementById('chk-upper');
      const chkLower  = document.getElementById('chk-lower');
      const chkNumber = document.getElementById('chk-number');

      function setCheck(el, ok) {
        if (!el) return;
        el.classList.toggle('ok', ok);
        el.querySelector('.check-icon').textContent = ok ? '✓' : '';
      }

      function updateChecklist() {
        const val = pwInput.value;
        setCheck(chkLength, val.length >= minLen);
        if (complexity) {
          setCheck(chkUpper,  /[A-Z]/.test(val));
          setCheck(chkLower,  /[a-z]/.test(val));
          setCheck(chkNumber, /[0-9]/.test(val));
        }
        // Update i18n placeholder for min-length text
        if (chkLength) {
          const span = chkLength.querySelector('[data-i18n-min]');
          if (span) {
            const key = span.dataset.i18nMin;
            const lang = I18N[currentLang] || I18N['en'] || {};
            const tpl  = lang[key] || `At least ${minLen} characters`;
            span.textContent = tpl.replace('{n}', minLen);
          }
        }
      }

      pwInput.addEventListener('input', updateChecklist);
      updateChecklist();
    })();

    // ── HaveIBeenPwned Check ────────────────────────────────────────────────
    <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
    (function() {
      const pwInput    = document.getElementById('passwd');
      const hibpStatus = document.getElementById('hibpStatus');
      const form       = document.getElementById('regForm');
      if (!pwInput || !hibpStatus) return;

      const blockOnBreach = <?= defined('HIBP_BLOCK_ON_BREACH') && HIBP_BLOCK_ON_BREACH ? 'true' : 'false' ?>;
      let hibpTimer = null;
      let lastBreach = false;

      // Compute SHA-1 using Web Crypto API (no external lib needed)
      async function sha1(str) {
        const buf  = new TextEncoder().encode(str);
        const hash = await crypto.subtle.digest('SHA-1', buf);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      }

      async function checkHibp(password) {
        if (password.length < 4) {
          hibpStatus.className = 'hibp-status';
          lastBreach = false;
          return;
        }

        const lang = I18N[currentLang] || I18N['en'] || {};
        hibpStatus.className = 'hibp-status checking';
        hibpStatus.textContent = lang.pw_hibp_checking || 'Checking password security...';

        try {
          const hash   = await sha1(password);
          const prefix = hash.substring(0, 5);
          const suffix = hash.substring(5);

          const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { 'Add-Padding': 'true' }
          });
          if (!resp.ok) throw new Error('HIBP API error');

          const text = await resp.text();
          let count  = 0;
          for (const line of text.split('\n')) {
            const [s, c] = line.trim().split(':');
            if (s && s.toUpperCase() === suffix) {
              count = parseInt(c, 10) || 1;
              break;
            }
          }

          if (count > 0) {
            lastBreach = true;
            hibpStatus.className = 'hibp-status warning';
            const tpl = lang.pw_hibp_warning || '⚠️ This password appeared in {n} data breach(es).';
            hibpStatus.textContent = tpl.replace('{n}', count.toLocaleString());
          } else {
            lastBreach = false;
            hibpStatus.className = 'hibp-status ok';
            hibpStatus.textContent = lang.pw_hibp_ok || '✓ Password not found in known data breaches.';
          }
        } catch (e) {
          // Fail-silent: do not block on API unavailability
          hibpStatus.className = 'hibp-status';
          lastBreach = false;
        }
      }

      pwInput.addEventListener('input', function() {
        clearTimeout(hibpTimer);
        hibpTimer = setTimeout(() => checkHibp(pwInput.value), 800);
      });

      // Block form submission if breach found and HIBP_BLOCK_ON_BREACH is enabled
      if (blockOnBreach && form) {
        form.addEventListener('submit', function(e) {
          if (lastBreach) {
            e.preventDefault();
            const lang = I18N[currentLang] || I18N['en'] || {};
            hibpStatus.className = 'hibp-status warning';
            hibpStatus.textContent = lang.pw_hibp_warning
              ? lang.pw_hibp_warning.replace('{n}', '?')
              : '⚠️ Please choose a different password.';
            pwInput.focus();
          }
        }, true);
      }
    })();
    <?php endif; ?>

  </script>

  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
  <script>
    // ── Cookie Consent Banner ──────────────────────────────────────────────────
    (function () {
      const banner = document.getElementById('cookieBanner');
      if (!banner) return;
      const COOKIE_KEY = 'isp_cookie_consent';

      if (localStorage.getItem(COOKIE_KEY) !== '1') {
        // Slide in after a short delay so the page settles first
        setTimeout(() => banner.classList.add('visible'), 400);
      }

      const acceptBtn = document.getElementById('cookieAcceptBtn');
      if (acceptBtn) {
        acceptBtn.addEventListener('click', function () {
          localStorage.setItem(COOKIE_KEY, '1');
          banner.classList.remove('visible');
          banner.addEventListener('transitionend', () => banner.remove(), { once: true });
        });
      }
    })();
  </script>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
  <script>
    // ── Accessibility Widget ───────────────────────────────────────────────────
    (function () {
      const toggleBtn  = document.getElementById('a11yToggleBtn');
      const panel      = document.getElementById('a11yPanel');
      const fontDecBtn = document.getElementById('a11yFontDec');
      const fontIncBtn = document.getElementById('a11yFontInc');
      const fontLabel  = document.getElementById('a11yFontSize');
      const contrastCb = document.getElementById('a11yContrast');
      const grayscaleCb = document.getElementById('a11yGrayscale');
      const motionCb   = document.getElementById('a11yMotion');

      const STORE = 'isp_a11y';
      let state = { font: 100, contrast: false, grayscale: false, motion: false };

      try {
        const saved = JSON.parse(localStorage.getItem(STORE) || 'null');
        if (saved) state = { ...state, ...saved };
      } catch (e) {}

      function save() {
        try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) {}
      }

      function applyAll() {
        document.documentElement.style.fontSize = state.font + '%';
        fontLabel.textContent = state.font + '%';
        document.documentElement.classList.toggle('a11y-contrast', state.contrast);
        document.documentElement.classList.toggle('a11y-grayscale', state.grayscale);
        document.documentElement.classList.toggle('a11y-motion', state.motion);
        contrastCb.checked  = state.contrast;
        grayscaleCb.checked = state.grayscale;
        motionCb.checked    = state.motion;
      }

      // Inject global a11y CSS rules once
      if (!document.getElementById('a11y-rules')) {
        const style = document.createElement('style');
        style.id = 'a11y-rules';
        style.textContent = [
          '.a11y-contrast { filter: contrast(1.6) brightness(1.05); }',
          '.a11y-grayscale { filter: grayscale(1); }',
          '.a11y-contrast.a11y-grayscale { filter: contrast(1.6) brightness(1.05) grayscale(1); }',
          '.a11y-motion *, .a11y-motion *::before, .a11y-motion *::after { animation-duration: 0.001ms !important; transition-duration: 0.001ms !important; }'
        ].join('\n');
        document.head.appendChild(style);
      }

      applyAll();

      // Toggle panel
      toggleBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        const open = panel.classList.toggle('open');
        toggleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });

      // Close on outside click
      document.addEventListener('click', function (e) {
        const widget = document.getElementById('a11yWidget');
        if (widget && !widget.contains(e.target)) {
          panel.classList.remove('open');
          toggleBtn.setAttribute('aria-expanded', 'false');
        }
      });

      // Font size
      fontDecBtn.addEventListener('click', function () {
        state.font = Math.max(80, state.font - 10);
        applyAll(); save();
      });
      fontIncBtn.addEventListener('click', function () {
        state.font = Math.min(150, state.font + 10);
        applyAll(); save();
      });

      // Toggles
      contrastCb.addEventListener('change', function () {
        state.contrast = this.checked;
        applyAll(); save();
      });
      grayscaleCb.addEventListener('change', function () {
        state.grayscale = this.checked;
        applyAll(); save();
      });
      motionCb.addEventListener('change', function () {
        state.motion = this.checked;
        applyAll(); save();
      });
    })();
  </script>
  <?php endif; ?>
</body>

</html>