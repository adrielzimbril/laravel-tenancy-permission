<?php

namespace Oricodes\TenantPermission\Exceptions;

use Illuminate\Support\Collection;
use InvalidArgumentException;

class TenantDoesNotMatch extends InvalidArgumentException
{
    public static function create(string $givenTenant, Collection $expectedTenants)
    : static {
        return new static("The given role or permission should use tenant `{$expectedTenants->implode(', ')}` instead of `{$givenTenant}`.");
    }
}
