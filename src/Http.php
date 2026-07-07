<?php

declare(strict_types=1);

namespace Sclemance\Oidc;

use Sclemance\Oidc\Exception\OidcException;

/**
 * Minimal outbound HTTP client with no hard dependency on ext-curl.
 *
 * Transport: PHP streams (allow_url_fopen) by default — part of PHP core and thus the most
 * broadly available — falling back to ext-curl only when allow_url_fopen is disabled. TLS
 * certificate verification is always on.
 *
 * @internal
 */
final class Http
{
    public function __construct(private int $timeout = 15)
    {
    }

    /**
     * GET a URL and JSON-decode the body. Throws on transport error or non-2xx.
     *
     * @return array<string,mixed>
     */
    public function getJson(string $url): array
    {
        [$status, $body] = $this->request('GET', $url, [], null);
        return $this->decode($url, $status, $body);
    }

    /**
     * POST application/x-www-form-urlencoded and JSON-decode the body.
     * Does NOT throw on non-2xx (OAuth token endpoints return useful JSON error bodies);
     * the caller inspects the decoded payload.
     *
     * @param array<string,scalar> $fields
     * @param array<string,string> $headers
     * @return array{status:int, body:array<string,mixed>}
     */
    public function postForm(string $url, array $fields, array $headers = []): array
    {
        $headers['Content-Type'] = 'application/x-www-form-urlencoded';
        [$status, $body] = $this->request('POST', $url, $headers, http_build_query($fields));
        $decoded = json_decode($body, true);
        return [
            'status' => $status,
            'body'   => is_array($decoded) ? $decoded : [],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private function decode(string $url, int $status, string $body): array
    {
        if ($status < 200 || $status >= 300) {
            throw new OidcException("HTTP {$status} from {$url}");
        }
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            throw new OidcException("Invalid JSON from {$url}");
        }
        return $decoded;
    }

    /**
     * @param array<string,string> $headers
     * @return array{0:int, 1:string} [status, body]
     */
    private function request(string $method, string $url, array $headers, ?string $body): array
    {
        if (ini_get('allow_url_fopen')) {
            return $this->viaStreams($method, $url, $headers, $body);
        }
        if (extension_loaded('curl')) {
            return $this->viaCurl($method, $url, $headers, $body);
        }
        throw new OidcException('No HTTP transport available: enable allow_url_fopen or ext-curl.');
    }

    /**
     * @param array<string,string> $headers
     * @return array{0:int, 1:string}
     */
    private function viaStreams(string $method, string $url, array $headers, ?string $body): array
    {
        $headerLines = [];
        foreach ($headers as $k => $v) {
            $headerLines[] = "$k: $v";
        }
        $context = stream_context_create([
            'http' => [
                'method'        => $method,
                'header'        => implode("\r\n", $headerLines),
                'content'       => $body ?? '',
                'timeout'       => $this->timeout,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ]);
        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            throw new OidcException("Request to {$url} failed (connection/TLS error).");
        }
        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $status = (int) $m[1];
            }
        }
        return [$status, $result];
    }

    /**
     * @param array<string,string> $headers
     * @return array{0:int, 1:string}
     */
    private function viaCurl(string $method, string $url, array $headers, ?string $body): array
    {
        $flat = [];
        foreach ($headers as $k => $v) {
            $flat[] = "$k: $v";
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $flat,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $result = curl_exec($ch);
        if ($result === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new OidcException("Request to {$url} failed: {$err}");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        return [$status, (string) $result];
    }
}
