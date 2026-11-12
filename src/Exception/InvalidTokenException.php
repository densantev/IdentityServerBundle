<?php

namespace Denux\IdentityServerBundle\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class InvalidTokenException extends AuthenticationException
{
    public function __construct()
    {
        parent::__construct('The bearer token is invalid.');
    }
}
