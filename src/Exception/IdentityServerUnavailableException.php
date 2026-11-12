<?php

namespace Denux\IdentityServerBundle\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class IdentityServerUnavailableException extends AuthenticationException
{
    public function __construct()
    {
        parent::__construct('The identity server is unavailable.');
    }
}
