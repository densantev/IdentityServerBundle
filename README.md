# IdentityServerBundle
Reusable Symfony bundle for validating incoming JWTs from a trusted IdentityServer and acquiring OAuth 2.0 Client Credentials access tokens for outgoing API calls.

## Installation

```bash
composer require denux/identity-server-bundle
```

Then register the bundle in the consuming app:

```php
// config/bundles.php
return [
    Denux\IdentityServerBundle\IdentityServerBundle::class => ['all' => true],
];
```

```yaml
# config/packages/identity_server.yaml
identity_server:
    issuer: '%env(resolve:IDENTITY_SERVER_ISSUER)%'
    audience: '%env(resolve:IDENTITY_SERVER_AUDIENCE)%'
    jwks_uri: '%env(resolve:IDENTITY_SERVER_JWKS_URI)%'
    jwks_cache_ttl: 300
    clock_skew: 30
```

## Incoming bearer JWTs

The bundle validates only `RS256` JWTs signed by keys presented in the configured JWKS. It confirms the signature, exact issuer, configured audience, expiration and optional `nbf`, uses a small clock skew, and refreshes JWKS on unknown `kid` values. Machine-to-machine tokens without `sub` are accepted when `client_id` is present.

The `IdentityServerAuthenticator` is intended for a stateless API firewall, while the existing form-login firewall in the app remains unchanged.

```yaml
security:
    firewalls:
        api:
            pattern: ^/api
            stateless: true
            custom_authenticators:
                - Denux\IdentityServerBundle\Security\IdentityServerAuthenticator
        main:
            # keep the existing form_login firewall here
```

Use Symfony access checks for scope and permission attributes:

```php
#[IsGranted('SCOPE_catalog.read')]
public function list(): Response
{
    // ...
}

#[IsGranted('PERMISSION_catalog.export')]
public function export(): Response
{
    // ...
}
```

## Outgoing Client Credentials

```php
$token = $provider->getAccessToken(
    'https://issuer.example/connect/token',
    'client-id',
    'client-secret',
    ['catalog.read']
);
```

The provider sends `grant_type=client_credentials`, uses HTTP Basic auth, and caches tokens in `cache.app` until a low refresh margin before expiration. It never logs secrets or raw token payloads. Store credentials in environment variables or Symfony secrets.

No live STS or contract is assumed; verify issuer, audience and endpoints against the actual provider before production use.
