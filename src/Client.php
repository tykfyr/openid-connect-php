<?php

namespace Tykfyr\OpenIDConnect;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use InvalidArgumentException;
use RuntimeException;

/**
 * OpenID Connect Client implementation
 * 
 * This class provides a simple way to integrate OpenID Connect authentication
 * into PHP applications. It handles the complete authentication flow including
 * token validation and user information retrieval.
 */
class Client
{
    /** @var string The base URL of the OpenID Connect provider */
    private string $providerUrl;

    /** @var string The client ID issued by the OpenID Connect provider */
    private string $clientId;

    /** @var string The client secret issued by the OpenID Connect provider */
    private string $clientSecret;

    /** @var array Default scopes to request during authentication */
    private array $scopes = ['openid', 'profile', 'email'];

    /** @var array Response types to request from the provider */
    private array $responseTypes = ['code'];

    /** @var string|null The redirect URI registered with the provider */
    private ?string $redirectUri = null;

    /** @var string|null The state parameter for CSRF protection */
    private ?string $state = null;

    /** @var string|null The nonce parameter for replay protection */
    private ?string $nonce = null;

    /** @var array Cached provider configuration */
    private array $providerConfig = [];

    /** @var array Token response from the provider */
    private array $tokenResponse = [];

    /** @var array User information retrieved from the provider */
    private array $userInfo = [];

    /** @var bool Whether to verify the host during SSL handshake */
    private bool $verifyHost = true;

    /** @var bool Whether to verify the peer during SSL handshake */
    private bool $verifyPeer = true;

    /** @var string|null Path to SSL certificate for verification */
    private ?string $certPath = null;

    /** @var string|null HTTP proxy configuration */
    private ?string $httpProxy = null;

    /**
     * Create a new OpenID Connect client instance
     *
     * @param string $providerUrl The base URL of the OpenID Connect provider
     * @param string $clientId The client ID issued by the provider
     * @param string $clientSecret The client secret issued by the provider
     */
    public function __construct(
        string $providerUrl,
        string $clientId,
        string $clientSecret
    ) {
        $this->providerUrl = rtrim($providerUrl, '/');
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    /**
     * Set the scopes to request during authentication
     *
     * @param array $scopes Array of scope strings to request
     * @return self
     */
    public function setScopes(array $scopes): self
    {
        $this->scopes = $scopes;
        return $this;
    }

    /**
     * Set the redirect URI for the authentication flow
     *
     * @param string $redirectUri The redirect URI registered with the provider
     * @return self
     */
    public function setRedirectUri(string $redirectUri): self
    {
        $this->redirectUri = $redirectUri;
        return $this;
    }

    /**
     * Configure SSL host verification
     *
     * @param bool $verify Whether to verify the host during SSL handshake
     * @return self
     */
    public function setVerifyHost(bool $verify): self
    {
        $this->verifyHost = $verify;
        return $this;
    }

    /**
     * Configure SSL peer verification
     *
     * @param bool $verify Whether to verify the peer during SSL handshake
     * @return self
     */
    public function setVerifyPeer(bool $verify): self
    {
        $this->verifyPeer = $verify;
        return $this;
    }

    /**
     * Set the path to the SSL certificate for verification
     *
     * @param string $path Path to the certificate file
     * @return self
     */
    public function setCertPath(string $path): self
    {
        $this->certPath = $path;
        return $this;
    }

    /**
     * Configure HTTP proxy settings
     *
     * @param string $proxy Proxy URL in format http://host:port
     * @return self
     */
    public function setHttpProxy(string $proxy): self
    {
        $this->httpProxy = $proxy;
        return $this;
    }

    /**
     * Start the OpenID Connect authentication flow
     *
     * This method generates state and nonce parameters, then redirects
     * the user to the provider's authorization endpoint.
     *
     * @return void
     */
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

    /**
     * Handle the callback from the OpenID Connect provider
     *
     * This method processes the authorization code, exchanges it for tokens,
     * and validates the ID token.
     *
     * @throws RuntimeException If the authorization code is missing or invalid
     * @return void
     */
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

    /**
     * Request user information from the provider
     *
     * @param string|null $claim Specific claim to retrieve, or null for all claims
     * @return mixed The requested claim value or all user information
     * @throws RuntimeException If no access token is available
     */
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

    /**
     * Get a configuration value from the provider's discovery document
     *
     * @param string $key The configuration key to retrieve
     * @return string The configuration value
     * @throws RuntimeException If the configuration value is not found
     */
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

    /**
     * Make an HTTP request to the provider
     *
     * @param string $url The URL to request
     * @param array $params POST parameters, if any
     * @param array $headers Additional HTTP headers
     * @return array The JSON-decoded response
     * @throws RuntimeException If the request fails or the response is invalid
     */
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

    /**
     * Validate the ID token received from the provider
     *
     * This method verifies the token's signature, expiration, and claims
     * including the nonce, issuer, and audience.
     *
     * @param string $idToken The ID token to validate
     * @throws RuntimeException If the token is invalid
     * @return void
     */
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