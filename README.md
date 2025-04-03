# OpenID Connect PHP Client

A simple OpenID Connect client library for PHP that makes it easy to integrate OpenID Connect authentication into your PHP applications.

## Requirements

- PHP 7.4 or higher
- cURL extension
- JSON extension

## Installation

```bash
composer require tykfyr/openid-connect-php
```

## Usage

### Basic Authentication Flow

```php
use Tykfyr\OpenIDConnect\Client;

// Initialize the client
$oidc = new Client(
    'https://your-identity-provider.com',
    'your-client-id',
    'your-client-secret'
);

// Set the redirect URI
$oidc->setRedirectUri('https://your-app.com/callback');

// Start authentication
$oidc->authenticate();

// In your callback handler
$oidc->handleCallback();

// Get user information
$userInfo = $oidc->requestUserInfo();
$email = $oidc->requestUserInfo('email');
```

### Advanced Configuration

```php
// Configure SSL verification
$oidc->setVerifyHost(false); // Disable host verification (not recommended for production)
$oidc->setVerifyPeer(false); // Disable peer verification (not recommended for production)

// Set custom certificate path
$oidc->setCertPath('/path/to/cert.pem');

// Configure proxy
$oidc->setHttpProxy('http://proxy.example.com:8080');

// Set custom scopes
$oidc->setScopes(['openid', 'profile', 'email', 'custom_scope']);
```

## Features

- Full OpenID Connect authentication flow
- Automatic discovery of provider configuration
- JWT token validation
- User info endpoint support
- Configurable SSL verification
- Proxy support
- Custom scopes support

## Security Considerations

- Always use HTTPS in production
- Keep your client secret secure
- Validate the state parameter
- Verify the ID token
- Use appropriate scopes for your needs

## License

This project is licensed under the MIT License - see the LICENSE file for details. 