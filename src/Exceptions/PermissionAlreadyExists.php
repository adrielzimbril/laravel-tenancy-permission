<?php

namespace Oricodes\TenantPermission\Exceptions;

use InvalidArgumentException;

class PermissionAlreadyExists extends InvalidArgumentException
{
    public static function create(string $permissionName, string $tenantName)
    {
        return new static("A `{$permissionName}` permission already exists for tenant `{$tenantName}`.");
    }
}
