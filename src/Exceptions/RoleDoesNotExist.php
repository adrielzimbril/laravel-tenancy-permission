<?php

namespace Oricodes\TenantPermission\Exceptions;

use InvalidArgumentException;

class RoleDoesNotExist extends InvalidArgumentException
{
    public static function named(string $roleName, ?string $tenantName)
    {
        return new static("There is no role named `{$roleName}` for tenant `{$tenantName}`.");
    }

    /**
     * @param  int|string  $roleId
     * @return static
     */
    public static function withId($roleId, ?string $tenantName)
    {
        return new static("There is no role with ID `{$roleId}` for tenant `{$tenantName}`.");
    }
}
