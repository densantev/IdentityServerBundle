<?php

namespace Denux\IdentityServerBundle\Security;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

final class TokenAccessVoter extends Voter
{
    protected function supports(string $attribute, mixed $subject): bool
    {
        return str_starts_with($attribute, 'SCOPE_') || str_starts_with($attribute, 'PERMISSION_');
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        if (!$user instanceof IdentityServerUser) {
            return false;
        }

        if (str_starts_with($attribute, 'SCOPE_')) {
            return $user->hasScope(substr($attribute, strlen('SCOPE_')));
        }

        return $user->hasPermission(substr($attribute, strlen('PERMISSION_')));
    }
}
