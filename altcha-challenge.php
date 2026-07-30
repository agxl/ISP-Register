<?php

/**
 * Developer: Andy Goldau
 * © 2026 ISP-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 * 
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * ISP-Register is an independent software solution and is not affiliated with, 
 * endorsed by, or sponsored by ISPConfig or its developers.
 */

require_once __DIR__ . '/config.php';

// Only allow ALTCHA provider to use this endpoint
if (CAPTCHA_PROVIDER !== 'altcha') {
    http_response_code(404);
    exit;
}

header('Content-Type: application/json');
header('Cache-Control: no-store, no-cache');

// Challenge TTL: 5 minutes
$expires   = time() + 300;
$salt      = bin2hex(random_bytes(12)) . '?expires=' . $expires;
$maxnumber = 100000;
$secret    = random_int(0, $maxnumber);
$challenge = hash('sha256', $salt . $secret);
$signature = hash_hmac('sha256', $challenge, ALTCHA_HMAC_KEY);

echo json_encode([
    'algorithm' => 'SHA-256',
    'challenge' => $challenge,
    'maxnumber' => $maxnumber,
    'salt'      => $salt,
    'signature' => $signature,
]);
