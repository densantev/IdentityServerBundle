<?php

namespace Denux\IdentityServerBundle\Security;

use Denux\IdentityServerBundle\Exception\IdentityServerUnavailableException;
use Denux\IdentityServerBundle\Exception\InvalidTokenException;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class IdentityServerTokenVerifier
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly string $jwksUri,
        private readonly int $jwksCacheTtl,
        private readonly int $clockSkew,
    ) {
    }

    public function verify(string $jwt): IdentityServerUser
    {
        try {
            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                throw new InvalidTokenException();
            }

            [$headerSegment, $payloadSegment, $signatureSegment] = $parts;
            $header = $this->decodeJsonSegment($headerSegment);
            $payload = $this->decodeJsonSegment($payloadSegment);

            if (($header['alg'] ?? null) !== 'RS256' || !is_string($header['kid'] ?? null) || $header['kid'] === '') {
                throw new InvalidTokenException();
            }

            $key = $this->findSigningKey($header['kid']);
            if ($key === null) {
                throw new InvalidTokenException();
            }

            $data = $headerSegment.'.'.$payloadSegment;
            $signature = $this->decodeBase64Url($signatureSegment);
            $publicKey = openssl_pkey_get_public($this->publicKeyPem($key));

            if ($publicKey === false || openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
                throw new InvalidTokenException();
            }

            return $this->createUser($payload);
        } catch (InvalidTokenException | IdentityServerUnavailableException $exception) {
            throw $exception;
        } catch (\Throwable) {
            throw new InvalidTokenException();
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findSigningKey(string $kid): ?array
    {
        foreach ($this->getSigningKeys() as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }

        $this->cache->delete('identity_server.jwks.'.hash('sha256', $this->jwksUri));
        foreach ($this->getSigningKeys() as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }

        return null;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function getSigningKeys(): array
    {
        /** @var mixed $keys */
        $keys = $this->cache->get('identity_server.jwks.'.hash('sha256', $this->jwksUri), function (ItemInterface $item): array {
            $item->expiresAfter($this->jwksCacheTtl);

            try {
                $response = $this->httpClient->request('GET', $this->jwksUri, [
                    'headers' => ['Accept' => 'application/json'],
                    'timeout' => 5,
                ]);
                if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300) {
                    throw new IdentityServerUnavailableException();
                }

                $document = json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);
            } catch (TransportExceptionInterface | \JsonException $exception) {
                throw new IdentityServerUnavailableException();
            }

            if (!is_array($document) || !is_array($document['keys'] ?? null)) {
                throw new IdentityServerUnavailableException();
            }

            return array_values(array_filter($document['keys'], static fn (mixed $key): bool => is_array($key)));
        });

        if (!is_array($keys)) {
            throw new IdentityServerUnavailableException();
        }

        return $keys;
    }

    /**
     * @param array<string, mixed> $key
     */
    private function publicKeyPem(array $key): string
    {
        if (($key['kty'] ?? null) !== 'RSA' || (isset($key['use']) && $key['use'] !== 'sig') || (isset($key['alg']) && $key['alg'] !== 'RS256')) {
            throw new InvalidTokenException();
        }

        if (!is_string($key['n'] ?? null) || !is_string($key['e'] ?? null)) {
            throw new InvalidTokenException();
        }

        $modulus = $this->decodeBase64Url($key['n']);
        $exponent = $this->decodeBase64Url($key['e']);

        $rsaPublicKey = $this->encodeDerSequence(
            $this->encodeDerInteger($modulus)
            .$this->encodeDerInteger($exponent)
        );

        return "-----BEGIN RSA PUBLIC KEY-----\n"
            .chunk_split(base64_encode($rsaPublicKey), 64, "\n")
            ."-----END RSA PUBLIC KEY-----\n";
    }

    private function encodeDerSequence(string $payload): string
    {
        return $this->encodeDerType(0x30, $payload);
    }

    private function encodeDerType(int $type, string $payload): string
    {
        return chr($type).$this->encodeDerLength(strlen($payload)).$payload;
    }

    private function encodeDerLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $bytes = [];
        while ($length > 0) {
            $bytes[] = chr($length & 0xFF);
            $length >>= 8;
        }

        $bytes = array_reverse($bytes);

        return chr(0x80 | count($bytes)).implode('', $bytes);
    }

    private function encodeDerInteger(string $value): string
    {
        $value = ltrim($value, "\0");
        if ($value === '') {
            $value = "\0";
        }

        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\0".$value;
        }

        return $this->encodeDerType(0x02, $value);
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeJsonSegment(string $segment): array
    {
        $decoded = json_decode($this->decodeBase64Url($segment), true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new InvalidTokenException();
        }

        return $decoded;
    }

    private function decodeBase64Url(string $value): string
    {
        if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/D', $value) !== 1) {
            throw new InvalidTokenException();
        }

        $decoded = base64_decode(strtr($value, '-_', '+/').str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if ($decoded === false) {
            throw new InvalidTokenException();
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function createUser(array $claims): IdentityServerUser
    {
        $now = time();

        if (($claims['iss'] ?? null) !== $this->issuer || !$this->hasAudience($claims['aud'] ?? null)) {
            throw new InvalidTokenException();
        }

        $exp = $claims['exp'] ?? null;
        if (!is_numeric($exp) || $now > (int) $exp + $this->clockSkew) {
            throw new InvalidTokenException();
        }

        if (isset($claims['nbf']) && (!is_numeric($claims['nbf']) || $now + $this->clockSkew < (int) $claims['nbf'])) {
            throw new InvalidTokenException();
        }

        $subject = $claims['sub'] ?? null;
        $clientId = $claims['client_id'] ?? null;
        if ((!is_string($subject) || $subject === '') && (!is_string($clientId) || $clientId === '')) {
            throw new InvalidTokenException();
        }

        return new IdentityServerUser(
            is_string($subject) && $subject !== '' ? $subject : $clientId,
            $this->claimList($claims['scope'] ?? null, true),
            array_values(array_unique(array_merge(
                $this->claimList($claims['permission'] ?? null, false),
                $this->claimList($claims['permissions'] ?? null, false)
            )))
        );
    }

    private function hasAudience(mixed $audience): bool
    {
        if ($audience === $this->audience) {
            return true;
        }

        return is_array($audience) && in_array($this->audience, $audience, true);
    }

    /**
     * @return list<string>
     */
    private function claimList(mixed $claim, bool $spaceDelimited): array
    {
        if ($claim === null) {
            return [];
        }

        if (is_string($claim)) {
            $claim = $spaceDelimited ? preg_split('/\s+/', trim($claim), -1, PREG_SPLIT_NO_EMPTY) : [$claim];
        }

        if (!is_array($claim)) {
            throw new InvalidTokenException();
        }

        $values = [];
        foreach ($claim as $value) {
            if (!is_string($value) || $value === '') {
                throw new InvalidTokenException();
            }
            $values[] = $value;
        }

        return array_values(array_unique($values));
    }
}
