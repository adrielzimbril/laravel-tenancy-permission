<?php

namespace Oricodes\TenantPermission\Exceptions;

use InvalidArgumentException;

class PermissionDoesNotExist extends InvalidArgumentException
{
    public static function create(string $permissionName, ?string $tenantName)
    {
        return new static("There is no permission named `{$permissionName}` for guard `{$tenantName}`.");
    }

    /**
     * @param  int|string  $permissionId
     * @return static
     */
    public static function withId($permissionId, ?string $tenantName)
    {
        return new static("There is no [permission] with ID `{$permissionId}` for guard `{$tenantName}`.");
    }
}
