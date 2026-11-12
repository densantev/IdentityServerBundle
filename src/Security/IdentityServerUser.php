<?php

namespace Denux\IdentityServerBundle\Security;

use Symfony\Component\Security\Core\User\UserInterface;

final class IdentityServerUser implements UserInterface
{
    /**
     * @param list<string> $scopes
     * @param list<string> $permissions
     */
    public function __construct(
        private readonly string $identifier,
        private readonly array $scopes,
        private readonly array $permissions,
    ) {
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return ['ROLE_IDENTITY_SERVER_USER'];
    }

    public function eraseCredentials(): void
    {
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }
}
