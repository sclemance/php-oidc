<?php

declare(strict_types=1);

/**
 * Self-contained test runner (no network, no real IdP, no PHPUnit).
 *
 *   php tests/run.php
 *
 * Part 1 exercises the crypto (JWK->PEM + JWT verify/validate) with a locally generated RSA
 * key. Part 2 launches a mock OIDC provider (PHP built-in server) and drives the full
 * Authorization Code flow through the public Oidc API.
 */

// CLI only. This runner spawns a subprocess (php -S); never allow it to run over HTTP.
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This test runner is command-line only.');
}

require __DIR__ . '/../autoload.php';

use Sclemance\Oidc\Jwk;
use Sclemance\Oidc\Jwt;
use Sclemance\Oidc\Oidc;
use Sclemance\Oidc\Config;
use Sclemance\Oidc\Cache\CacheInterface;
use Sclemance\Oidc\Session\SessionStoreInterface;
use Sclemance\Oidc\Exception\AuthenticationException;
use Sclemance\Oidc\Exception\ConfigException;

$pass = 0;
$fail = 0;
function ok(bool $cond, string $msg): void
{
    global $pass, $fail;
    if ($cond) { $pass++; echo "  PASS  $msg\n"; }
    else       { $fail++; echo "  FAIL  $msg\n"; }
}
function b64u(string $b): string { return rtrim(strtr(base64_encode($b), '+/', '-_'), '='); }

// In-memory session/cache so scenarios are isolated and no PHP session is required.
final class ArraySession implements SessionStoreInterface
{
    /** @var array<string,mixed> */
    public array $d = [];
    public function get(string $k): mixed { return $this->d[$k] ?? null; }
    public function set(string $k, mixed $v): void { $this->d[$k] = $v; }
    public function remove(string $k): void { unset($this->d[$k]); }
    public function regenerate(): void {}
}
final class ArrayCache implements CacheInterface
{
    /** @var array<string,array<string,mixed>> */
    public array $d = [];
    public function get(string $k): ?array { return $this->d[$k] ?? null; }
    public function set(string $k, array $v, int $t): void { $this->d[$k] = $v; }
}

// ---------------------------------------------------------------------------------------
echo "Part 1: crypto (JWK->PEM, JWT verify/validate)\n";
// ---------------------------------------------------------------------------------------
$kp = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($kp, $privPem);
$det = openssl_pkey_get_details($kp);
$jwk = ['kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'alg' => 'RS256',
        'n' => b64u($det['rsa']['n']), 'e' => b64u($det['rsa']['e'])];

$mint = static function (string $priv, array $over = [], array $header = []): string {
    $h = array_merge(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'k1'], $header);
    $c = array_merge(['iss' => 'https://iss.test', 'aud' => 'client', 'sub' => 's1',
                      'email' => 'u@x.test', 'iat' => time(), 'exp' => time() + 300], $over);
    $si = b64u((string) json_encode($h)) . '.' . b64u((string) json_encode($c));
    openssl_sign($si, $sig, $priv, OPENSSL_ALGO_SHA256);
    return $si . '.' . b64u($sig);
};

$pem = Jwk::toPemFromSet([$jwk], 'k1');
ok(str_contains($pem, 'BEGIN PUBLIC KEY'), 'JWK -> PEM produces a public key');

$tok = $mint($privPem, ['nonce' => 'n1']);
$p = Jwt::parse($tok);
try { Jwt::verifySignature($p['header'], $p['signingInput'], $p['signature'], $pem); ok(true, 'valid signature verifies'); }
catch (Throwable $e) { ok(false, 'valid signature verifies: ' . $e->getMessage()); }
try { Jwt::validateClaims($p['payload'], 'https://iss.test', 'client', 'n1', 60); ok(true, 'valid claims pass'); }
catch (Throwable $e) { ok(false, 'valid claims pass: ' . $e->getMessage()); }

$bad = $tok . 'x';
try { $bp = Jwt::parse($bad); Jwt::verifySignature($bp['header'], $bp['signingInput'], $bp['signature'], $pem); ok(false, 'tampered rejected'); }
catch (AuthenticationException $e) { ok(true, 'tampered signature rejected'); }

foreach ([
    ['bad nonce',   fn() => Jwt::validateClaims($p['payload'], 'https://iss.test', 'client', 'WRONG', 60)],
    ['expired',     fn() => Jwt::validateClaims(['iss'=>'https://iss.test','aud'=>'client','exp'=>time()-100], 'https://iss.test', 'client', null, 60)],
    ['wrong aud',   fn() => Jwt::validateClaims($p['payload'], 'https://iss.test', 'other', 'n1', 60)],
    ['wrong iss',   fn() => Jwt::validateClaims($p['payload'], 'https://evil.test', 'client', 'n1', 60)],
] as [$name, $fn]) {
    try { $fn(); ok(false, "$name rejected"); }
    catch (AuthenticationException $e) { ok(true, "$name rejected"); }
}

// ---------------------------------------------------------------------------------------
echo "Part 2: full Authorization Code flow against a mock provider\n";
// ---------------------------------------------------------------------------------------
$tmp = sys_get_temp_dir() . '/php-oidc-test-' . bin2hex(random_bytes(4));
@mkdir($tmp, 0700, true);
file_put_contents("$tmp/priv.pem", $privPem);
file_put_contents("$tmp/jwks.json", (string) json_encode(['keys' => [$jwk]]));

// Mock provider script.
file_put_contents("$tmp/idp.php", <<<'PHP'
<?php
$issuer = getenv('MOCK_ISSUER');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
header('Content-Type: application/json');
switch ($path) {
  case '/.well-known/openid-configuration':
    echo json_encode(['issuer'=>$issuer,'authorization_endpoint'=>"$issuer/authorize",
      'token_endpoint'=>"$issuer/token",'jwks_uri'=>"$issuer/jwks",
      'end_session_endpoint'=>"$issuer/logout"]); break;
  case '/jwks':  readfile(getenv('JWKS_FILE')); break;
  case '/token': readfile(getenv('TOKEN_FILE')); break;
  default: http_response_code(404); echo '{}';
}
PHP);

// Grab a free port.
$probe = stream_socket_server('tcp://127.0.0.1:0', $en, $es);
$port = (int) substr((string) stream_socket_get_name($probe, false), strrpos((string) stream_socket_get_name($probe, false), ':') + 1);
fclose($probe);

$issuer = "http://127.0.0.1:$port";
$client = 'client';
$tokenFile = "$tmp/token.json";
$env = ['MOCK_ISSUER' => $issuer, 'JWKS_FILE' => "$tmp/jwks.json", 'TOKEN_FILE' => $tokenFile]
     + array_map('strval', $_ENV) + ['PATH' => getenv('PATH')];

$proc = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:$port", "$tmp/idp.php"],
    [0 => ['pipe', 'r'], 1 => ['file', "$tmp/idp.out", 'w'], 2 => ['file', "$tmp/idp.err", 'w']],
    $pipes,
    $tmp,
    $env
);

// Wait for readiness.
$ready = false;
for ($i = 0; $i < 50; $i++) {
    $c = @stream_socket_client("tcp://127.0.0.1:$port", $e1, $e2, 0.2);
    if ($c) { fclose($c); $ready = true; break; }
    usleep(100000);
}
ok($ready, 'mock provider is reachable');

$writeToken = static function (string $file, string $idToken): void {
    file_put_contents($file, (string) json_encode([
        'id_token' => $idToken, 'access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 300]));
};
$mintFor = static function (string $priv, string $issuer, string $client, array $over = []) use ($mint): string {
    return $mint($priv, array_merge(['iss' => $issuer, 'aud' => $client], $over));
};
$cfg = static function (ArraySession $s, ArrayCache $c, string $issuer, string $client, array $extra = []): array {
    return array_merge(['issuer' => $issuer, 'client_id' => $client, 'client_secret' => 's',
        'redirect_uri' => 'http://app.test/cb', 'session' => $s, 'cache' => $c], $extra);
};

try {
    // Config validation
    try { new Config(['client_id' => 'x', 'redirect_uri' => 'y']); ok(false, 'config requires issuer'); }
    catch (ConfigException $e) { ok(true, 'config rejects missing issuer'); }

    // Happy path
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => 'http://app.test/home', 'ts' => time()]);
    $writeToken($tokenFile, $mintFor($privPem, $issuer, $client, ['nonce' => 'no']));
    $_GET = ['state' => 'st', 'code' => 'abc'];
    $u = (new Oidc($cfg($s, $c, $issuer, $client)))->handleCallback();
    ok($u->email() === 'u@x.test', 'happy path returns user');
    ok($s->get('user') !== null && $s->get('tx') === null, 'session established, tx cleared');

    // State mismatch
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'right', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $_GET = ['state' => 'wrong', 'code' => 'abc'];
    try { (new Oidc($cfg($s, $c, $issuer, $client)))->handleCallback(); ok(false, 'state mismatch'); }
    catch (AuthenticationException $e) { ok(str_contains($e->getMessage(), 'State'), 'state mismatch rejected'); }

    // Expired
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $writeToken($tokenFile, $mintFor($privPem, $issuer, $client, ['nonce' => 'no', 'exp' => time() - 200]));
    $_GET = ['state' => 'st', 'code' => 'abc'];
    try { (new Oidc($cfg($s, $c, $issuer, $client)))->handleCallback(); ok(false, 'expired'); }
    catch (AuthenticationException $e) { ok(str_contains($e->getMessage(), 'expired'), 'expired token rejected'); }

    // authorize policy denies
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $writeToken($tokenFile, $mintFor($privPem, $issuer, $client, ['nonce' => 'no', 'email' => 'x@evil.test']));
    $_GET = ['state' => 'st', 'code' => 'abc'];
    $conf = $cfg($s, $c, $issuer, $client, ['authorize' => fn($cl) => str_ends_with($cl['email'] ?? '', '@x.test')]);
    try { (new Oidc($conf))->handleCallback(); ok(false, 'authorize'); }
    catch (AuthenticationException $e) { ok(str_contains($e->getMessage(), 'not permitted'), 'authorize policy denies'); }

    // provider error
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $_GET = ['state' => 'st', 'error' => 'login_required'];
    try { (new Oidc($cfg($s, $c, $issuer, $client)))->handleCallback(); ok(false, 'provider error'); }
    catch (AuthenticationException $e) { ok($e->oauthError === 'login_required', 'provider error surfaced'); }

    // forged signature
    $rogue = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($rogue, $roguePem);
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $writeToken($tokenFile, $mintFor($roguePem, $issuer, $client, ['nonce' => 'no']));
    $_GET = ['state' => 'st', 'code' => 'abc'];
    try { (new Oidc($cfg($s, $c, $issuer, $client)))->handleCallback(); ok(false, 'forged'); }
    catch (AuthenticationException $e) { ok(str_contains($e->getMessage(), 'signature'), 'forged-signature rejected'); }

    // store_tokens => false: user returned with tokens in-memory, but NOT persisted
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $writeToken($tokenFile, $mintFor($privPem, $issuer, $client, ['nonce' => 'no']));
    $_GET = ['state' => 'st', 'code' => 'abc'];
    $o = new Oidc($cfg($s, $c, $issuer, $client, ['store_tokens' => false]));
    $u = $o->handleCallback();
    ok($u->accessToken() === 'at', 'store_tokens=false: token available this request');
    ok(($s->get('user')['tokens'] ?? []) === [], 'store_tokens=false: tokens not persisted');
    ok($o->user()?->accessToken() === null, 'store_tokens=false: no token in later request');

    // absolute timeout: a session older than the absolute TTL is treated as signed out
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $writeToken($tokenFile, $mintFor($privPem, $issuer, $client, ['nonce' => 'no']));
    $_GET = ['state' => 'st', 'code' => 'abc'];
    $o = new Oidc($cfg($s, $c, $issuer, $client, ['session_absolute_ttl' => 1]));
    $o->handleCallback();
    ok($o->isAuthenticated(), 'absolute ttl: authenticated immediately after login');
    $s->d['meta']['auth_time'] = time() - 10; // simulate 10s elapsed vs 1s TTL
    ok($o->user() === null, 'absolute ttl: expired session cleared');
    ok($s->get('user') === null, 'absolute ttl: user removed from store');

    // idle timeout: inactivity beyond idle TTL signs the user out
    $s = new ArraySession(); $c = new ArrayCache();
    $s->set('tx', ['state' => 'st', 'nonce' => 'no', 'verifier' => 'v', 'return' => '/', 'ts' => time()]);
    $writeToken($tokenFile, $mintFor($privPem, $issuer, $client, ['nonce' => 'no']));
    $_GET = ['state' => 'st', 'code' => 'abc'];
    $o = new Oidc($cfg($s, $c, $issuer, $client, ['session_idle_ttl' => 1]));
    $o->handleCallback();
    $s->d['meta']['last_seen'] = time() - 10;
    ok($o->user() === null, 'idle ttl: idle session cleared');

    // getAuthorizationUrl primitive: builds URL + tx, no redirect/exit
    $s = new ArraySession(); $c = new ArrayCache();
    $o = new Oidc($cfg($s, $c, $issuer, $client));
    $url = $o->getAuthorizationUrl('http://app.test/back');
    ok(str_contains($url, "$issuer/authorize") && str_contains($url, 'code_challenge='), 'getAuthorizationUrl returns URL with PKCE');
    ok(($s->get('tx')['return'] ?? null) === 'http://app.test/back', 'getAuthorizationUrl stored return + tx');

    // getLogoutUrl primitive
    $logout = $o->getLogoutUrl('http://app.test/bye', 'idhint');
    ok($logout !== null && str_contains($logout, '/logout') && str_contains($logout, 'post_logout_redirect_uri='), 'getLogoutUrl builds end-session URL');
} finally {
    if (isset($proc) && is_resource($proc)) {
        proc_terminate($proc);
        proc_close($proc);
    }
    array_map('unlink', glob("$tmp/*") ?: []);
    @rmdir($tmp);
}

echo "\n==== $pass passed, $fail failed ====\n";
exit($fail === 0 ? 0 : 1);
