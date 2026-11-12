<?php

namespace Denux\IdentityServerBundle\Security;

use Denux\IdentityServerBundle\Exception\IdentityServerUnavailableException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class IdentityServerAuthenticator extends AbstractAuthenticator
{
    public function __construct(private readonly IdentityServerTokenVerifier $tokenVerifier)
    {
    }

    public function supports(Request $request): ?bool
    {
        $header = (string) $request->headers->get('Authorization', '');

        return preg_match('/^\s*Bearer\s+/i', $header) === 1;
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $authorization = (string) $request->headers->get('Authorization', '');
        if (preg_match('/^\s*Bearer\s+(\S+)\s*$/iD', $authorization, $matches) !== 1) {
            throw new AuthenticationException('The bearer token is invalid.');
        }

        $user = $this->tokenVerifier->verify($matches[1]);

        return new SelfValidatingPassport(new UserBadge(
            $user->getUserIdentifier(),
            static fn (): UserInterface => $user,
        ));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $status = $exception instanceof IdentityServerUnavailableException ? Response::HTTP_SERVICE_UNAVAILABLE : Response::HTTP_UNAUTHORIZED;

        return new JsonResponse(['error' => $status === Response::HTTP_UNAUTHORIZED ? 'invalid_token' : 'identity_server_unavailable'], $status);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new JsonResponse(['error' => 'authentication_required'], Response::HTTP_UNAUTHORIZED);
    }
}
