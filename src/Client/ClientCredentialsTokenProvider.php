<?php

namespace Denux\IdentityServerBundle\Client;

use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class ClientCredentialsTokenProvider
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
    ) {
    }

    /**
     * @param list<string> $scopes
     */
    public function getAccessToken(string $tokenUrl, string $clientId, string $clientSecret, array $scopes = []): string
    {
        if ($tokenUrl === '' || $clientId === '' || $clientSecret === '') {
            throw new \InvalidArgumentException('Token URL and client credentials must not be empty.');
        }

        foreach ($scopes as $scope) {
            if (!is_string($scope) || $scope === '' || preg_match('/\s/', $scope) === 1) {
                throw new \InvalidArgumentException('Scopes must be non-empty strings without whitespace.');
            }
        }

        $scope = implode(' ', array_values(array_unique($scopes)));
        $cacheKey = 'identity_server.client_credentials.'.hash('sha256', json_encode([
            $tokenUrl,
            $clientId,
            hash('sha256', $clientSecret),
            $scope,
        ], JSON_THROW_ON_ERROR));

        return $this->cache->get($cacheKey, function (ItemInterface $item) use ($tokenUrl, $clientId, $clientSecret, $scope): string {
            try {
                $response = $this->httpClient->request('POST', $tokenUrl, [
                    'auth_basic' => [$clientId, $clientSecret],
                    'body' => array_filter([
                        'grant_type' => 'client_credentials',
                        'scope' => $scope !== '' ? $scope : null,
                    ], static fn (mixed $value): bool => $value !== null),
                    'headers' => ['Accept' => 'application/json'],
                    'timeout' => 5,
                ]);

                $statusCode = $response->getStatusCode();
                if ($statusCode < 200 || $statusCode >= 300) {
                    throw new \RuntimeException(sprintf('The identity server token endpoint returned HTTP %d.', $statusCode));
                }

                $payload = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);
            } catch (TransportExceptionInterface | \JsonException $exception) {
                throw new \RuntimeException('The identity server token endpoint could not be reached or replied with malformed JSON.', previous: $exception);
            }

            if (!is_array($payload) || !is_string($payload['access_token'] ?? null) || $payload['access_token'] === '' || !is_string($payload['token_type'] ?? null) || strcasecmp($payload['token_type'], 'Bearer') !== 0 || !is_numeric($payload['expires_in'] ?? null) || (int) $payload['expires_in'] < 1) {
                throw new \RuntimeException('The identity server returned an invalid token response.');
            }

            $expiresIn = (int) $payload['expires_in'];
            $refreshMargin = min(30, max(1, (int) floor($expiresIn * 0.1)));
            $item->expiresAfter(max(1, $expiresIn - $refreshMargin));

            return $payload['access_token'];
        });
    }
}
