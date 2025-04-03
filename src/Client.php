<?php

namespace Tykfyr\OpenIDConnect;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use InvalidArgumentException;
use RuntimeException;

class Client
{
    private string $providerUrl;
    private string $clientId;
    private string $clientSecret;
    private array $scopes = ['openid', 'profile', 'email'];
    private array $responseTypes = ['code'];
    private ?string $redirectUri = null;
    private ?string $state = null;
    private ?string $nonce = null;
    private array $providerConfig = [];
    private array $tokenResponse = [];
    private array $userInfo = [];
    private bool $verifyHost = true;
    private bool $verifyPeer = true;
    private ?string $certPath = null;
    private ?string $httpProxy = null;

    public function __construct(
        string $providerUrl,
        string $clientId,
        string $clientSecret
    ) {
        $this->providerUrl = rtrim($providerUrl, '/');
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    public function setScopes(array $scopes): self
    {
        $this->scopes = $scopes;
        return $this;
    }

    public function setRedirectUri(string $redirectUri): self
    {
        $this->redirectUri = $redirectUri;
        return $this;
    }

    public function setVerifyHost(bool $verify): self
    {
        $this->verifyHost = $verify;
        return $this;
    }

    public function setVerifyPeer(bool $verify): self
    {
        $this->verifyPeer = $verify;
        return $this;
    }

    public function setCertPath(string $path): self
    {
        $this->certPath = $path;
        return $this;
    }

    public function setHttpProxy(string $proxy): self
    {
        $this->httpProxy = $proxy;
        return $this;
    }

    public function authenticate(): void
    {
        $this->state = bin2hex(random_bytes(16));
        $this->nonce = bin2hex(random_bytes(16));

        $params = [
            'response_type' => implode(' ', $this->responseTypes),
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $this->state,
            'nonce' => $this->nonce,
            'scope' => implode(' ', $this->scopes)
        ];

        $authUrl = $this->getProviderConfigValue('authorization_endpoint') . '?' . http_build_query($params);
        
        header('Location: ' . $authUrl);
        exit;
    }

    public function handleCallback(): void
    {
        if (!isset($_GET['code'])) {
            throw new RuntimeException('Authorization code not found');
        }

        if (!isset($_GET['state']) || $_GET['state'] !== $this->state) {
            throw new RuntimeException('Invalid state parameter');
        }

        $tokenEndpoint = $this->getProviderConfigValue('token_endpoint');
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $_GET['code'],
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret
        ];

        $this->tokenResponse = $this->request($tokenEndpoint, $params);
        
        if (!isset($this->tokenResponse['id_token'])) {
            throw new RuntimeException('No ID token received');
        }

        $this->validateIdToken($this->tokenResponse['id_token']);
    }

    public function requestUserInfo(string $claim = null)
    {
        if (empty($this->tokenResponse['access_token'])) {
            throw new RuntimeException('No access token available');
        }

        $userInfoEndpoint = $this->getProviderConfigValue('userinfo_endpoint');
        $headers = [
            'Authorization: Bearer ' . $this->tokenResponse['access_token']
        ];

        $this->userInfo = $this->request($userInfoEndpoint, [], $headers);

        if ($claim !== null) {
            return $this->userInfo[$claim] ?? null;
        }

        return $this->userInfo;
    }

    private function getProviderConfigValue(string $key): string
    {
        if (empty($this->providerConfig)) {
            $this->providerConfig = $this->request($this->providerUrl . '/.well-known/openid-configuration');
        }

        if (!isset($this->providerConfig[$key])) {
            throw new RuntimeException("Provider configuration value '$key' not found");
        }

        return $this->providerConfig[$key];
    }

    private function request(string $url, array $params = [], array $headers = []): array
    {
        $ch = curl_init();
        
        if (!empty($params)) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        }

        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->verifyHost ? 2 : 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifyPeer);

        if ($this->certPath) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->certPath);
        }

        if ($this->httpProxy) {
            curl_setopt($ch, CURLOPT_PROXY, $this->httpProxy);
        }

        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new RuntimeException('Curl error: ' . $error);
        }

        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Invalid JSON response');
        }

        return $data;
    }

    private function validateIdToken(string $idToken): void
    {
        $keys = $this->request($this->getProviderConfigValue('jwks_uri'));
        
        if (!isset($keys['keys'])) {
            throw new RuntimeException('Invalid JWKS response');
        }

        $decoded = JWT::decode($idToken, new Key($keys['keys'][0], 'RS256'));
        
        if ($decoded->nonce !== $this->nonce) {
            throw new RuntimeException('Invalid nonce');
        }

        if ($decoded->iss !== $this->providerUrl) {
            throw new RuntimeException('Invalid issuer');
        }

        if ($decoded->aud !== $this->clientId) {
            throw new RuntimeException('Invalid audience');
        }

        if (isset($decoded->exp) && $decoded->exp < time()) {
            throw new RuntimeException('Token expired');
        }
    }
} 