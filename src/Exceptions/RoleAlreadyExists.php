<?php

namespace Oricodes\TenantPermission\Exceptions;

use InvalidArgumentException;

class RoleAlreadyExists extends InvalidArgumentException
{
    public static function create(string $roleName, string $tenantName)
    {
        return new static("A role `{$roleName}` already exists for guard `{$tenantName}`.");
    }
}
