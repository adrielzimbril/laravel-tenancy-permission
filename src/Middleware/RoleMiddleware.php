<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;

class RoleMiddleware
{
    /**
     * Specify the role and tenant for the middleware.
     *
     * @param array|string $role
     * @param string|null $tenant
     * @return string
     */
    public static function using(array | string $role, string $tenant = null)
    : string {
        $roleString = is_string($role) ? $role : implode('|', $role);
        $args = is_null($tenant) ? $roleString : "$roleString,$tenant";

        return static::class.':'.$args;
    }

    public function handle($request, Closure $next, $role, $tenant = null)
    {
        $user = $tenant ? tenant($tenant)->user : tenant()->user;

        if (! $user) {
            throw UnauthorizedException::notLoggedIn();
        }

        if (! method_exists($user, 'hasAnyRole')) {
            throw UnauthorizedException::missingTraitHasRoles($user);
        }

        $roles = is_array($role)
            ? $role
            : explode('|', $role);

        if (! $user->hasAnyRole($roles)) {
            throw UnauthorizedException::forRoles($roles);
        }

        return $next($request);
    }
}
