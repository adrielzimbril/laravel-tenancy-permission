<?php

namespace Oricodes\TenantPermission\Exceptions;

use InvalidArgumentException;

class WildcardPermissionNotImplementsContract extends InvalidArgumentException
{
    public static function create()
    {
        return new static('Wildcard permission class must implements Oricodes\TenantPermission\Contracts\Wildcard contract');
    }
}
