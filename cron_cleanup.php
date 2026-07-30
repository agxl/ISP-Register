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
 * Demo Mode Account Cleanup Script (Cronjob)
 * --------------------------------------------------
 * Deletes expired demo ISPConfig client accounts created by ISP-Register
 * via the ISPConfig remote JSON-RPC API (client_delete_everything).
 *
 * Setup (add to crontab on your server):
 *   crontab -e
 *   Add the following line (runs every 30 minutes):
 *   (asterisk)/30 * * * * php /path/to/public_html/cron_cleanup.php >> /dev/null 2>&1
 *   Note: replace (asterisk) with * in your crontab.
 *
 * Note: ISPConfig's client_delete_everything requires the numeric client_id,
 * which is stored in demo_accounts.json during registration (as 'client_id').
 */

// Prevent unauthorized direct HTTP access unless running via CLI or with valid CLI context
if (php_sapi_name() !== 'cli' && !defined('CRON_ALLOWED')) {
    header('HTTP/1.1 403 Forbidden');
    echo "Access denied. This script is intended to be run via command line (CLI cronjob).\n";
    exit(1);
}

// Set maximum execution time for batch account deletions
@set_time_limit(300);

// Load main configuration
$configPath = __DIR__ . '/config.php';
if (!is_file($configPath)) {
    echo "[" . date('Y-m-d H:i:s') . "] ERROR: Configuration file not found at $configPath\n";
    exit(1);
}
require_once $configPath;

// Check if Demo Mode is enabled
if (!defined('DEMO_MODE') || !DEMO_MODE) {
    echo "[" . date('Y-m-d H:i:s') . "] DEMO MODE IS DISABLED in config.php. Exiting.\n";
    exit(0);
}

$dataFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');

if (!is_file($dataFile)) {
    echo "[" . date('Y-m-d H:i:s') . "] No demo accounts file found ($dataFile). Nothing to clean up.\n";
    exit(0);
}

$raw      = file_get_contents($dataFile);
$accounts = json_decode((string) $raw, true);

if (!is_array($accounts) || empty($accounts)) {
    echo "[" . date('Y-m-d H:i:s') . "] Demo accounts list is empty. Nothing to clean up.\n";
    exit(0);
}

$now          = time();
$deletedCount = 0;
$keptCount    = 0;

echo "[" . date('Y-m-d H:i:s') . "] Starting demo accounts cleanup scan (" . count($accounts) . " accounts tracked)...\n";

// ── ISPConfig JSON-RPC helper ───────────────────────────────────────────────
/**
 * Sends a JSON-RPC call to the ISPConfig remote/json.php API.
 * Returns the decoded response array, or an empty array on failure.
 */
function cronIspJsonRpc(string $method, array $params, int $timeout = 30): array
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

/**
 * Deletes a demo client from ISPConfig using client_delete_everything.
 * Returns true on success, false on failure.
 * $clientId is the numeric ID stored during registration.
 */
function deleteIspClient(int $clientId, string $username): bool
{
    $timeout = defined('ISP_TIMEOUT') ? ISP_TIMEOUT : 90;

    // Step 1 – Login
    $loginResp = cronIspJsonRpc('login', [
        'username'     => ISP_REMOTE_USER,
        'password'     => ISP_REMOTE_PASS,
        'client_login' => false,
    ], 15);

    if (empty($loginResp) || ($loginResp['code'] ?? '') === 'login_failed') {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: ISPConfig API login failed for deletion of '$username' (client_id=$clientId).\n";
        return false;
    }

    $sessionId = $loginResp['response'] ?? null;
    if (!$sessionId) {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: No session_id returned from ISPConfig login.\n";
        return false;
    }

    // Step 2 – Delete client and all associated resources
    $deleteResp = cronIspJsonRpc('client_delete_everything', [
        'session_id' => $sessionId,
        'client_id'  => $clientId,
    ], $timeout);

    // Step 3 – Logout (always)
    cronIspJsonRpc('logout', ['session_id' => $sessionId], 10);

    $code = $deleteResp['code'] ?? '';

    if ($code === 'ok') {
        return true;
    }

    $reason = $deleteResp['message'] ?? ('Unknown response code: ' . $code);
    echo "[" . date('Y-m-d H:i:s') . "] WARNING: ISPConfig deletion response for '$username': $reason\n";

    // Treat "already gone" as success to avoid infinite retry loops
    if (stripos($reason, 'not exist') !== false || stripos($reason, 'not found') !== false) {
        return true;
    }

    return false;
}

// ── Process expired accounts ────────────────────────────────────────────────
foreach ($accounts as $username => $info) {
    $deleteAfter = (int) ($info['delete_after'] ?? 0);
    $clientId    = isset($info['client_id']) ? (int) $info['client_id'] : 0;

    if ($now >= $deleteAfter) {
        echo "[" . date('Y-m-d H:i:s') . "] Account '$username' (client_id=$clientId) expired "
            . "(Created: " . date('Y-m-d H:i:s', $info['created_at'] ?? 0) . "). "
            . "Terminating via ISPConfig API...\n";

        if ($clientId <= 0) {
            echo "[" . date('Y-m-d H:i:s') . "] ERROR: No valid client_id stored for '$username'. "
                . "Cannot delete via API. Removing from tracking list to prevent loop.\n";
            unset($accounts[$username]);
            continue;
        }

        $success = deleteIspClient($clientId, (string) $username);

        if ($success) {
            echo "[" . date('Y-m-d H:i:s') . "] SUCCESS: Account '$username' (client_id=$clientId) "
                . "deleted from ISPConfig.\n";
            unset($accounts[$username]);
            $deletedCount++;

            if (function_exists('auditLog')) {
                auditLog((string)$username, $info['email'] ?? '', $info['domain'] ?? '', 'demo_cleanup', 'account_terminated');
            }
        } else {
            echo "[" . date('Y-m-d H:i:s') . "] ERROR: Failed to delete account '$username' "
                . "(client_id=$clientId) from ISPConfig.\n";
        }
    } else {
        $remainingMin = ceil(($deleteAfter - $now) / 60);
        echo "[" . date('Y-m-d H:i:s') . "] Account '$username' active ($remainingMin minutes remaining).\n";
        $keptCount++;
    }
}

// Save updated accounts list
file_put_contents($dataFile, json_encode($accounts, JSON_PRETTY_PRINT), LOCK_EX);

echo "[" . date('Y-m-d H:i:s') . "] Cleanup complete. Deleted: $deletedCount account(s), Active: $keptCount account(s).\n";
