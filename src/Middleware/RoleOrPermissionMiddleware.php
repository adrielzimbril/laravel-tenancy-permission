<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;

class RoleOrPermissionMiddleware
{
    /**
     * Specify the role or permission and tenant for the middleware.
     *
     * @param array|string $roleOrPermission
     * @param string|null $tenant
     * @return string
     */
    public static function using(array | string $roleOrPermission, string $tenant = null)
    : string {
        $roleOrPermissionString = is_string($roleOrPermission) ? $roleOrPermission : implode('|', $roleOrPermission);
        $args = is_null($tenant) ? $roleOrPermissionString : "$roleOrPermissionString,$tenant";

        return static::class.':'.$args;
    }

    public function handle($request, Closure $next, $roleOrPermission, $tenant = 'tenant_user')
    {
        $user = $tenant ? tenant($tenant)->user : tenant()->user;

        if (! $user) {
            throw UnauthorizedException::notLoggedIn();
        }

        if (! method_exists($user, 'hasAnyRole') || ! method_exists($user, 'hasAnyPermission')) {
            throw UnauthorizedException::missingTraitHasRoles($user);
        }

        $rolesOrPermissions = is_array($roleOrPermission)
            ? $roleOrPermission
            : explode('|', $roleOrPermission);

        if (! $user->canAny($rolesOrPermissions) && ! $user->hasAnyRole($rolesOrPermissions)) {
            throw UnauthorizedException::forRolesOrPermissions($rolesOrPermissions);
        }

        return $next($request);
    }
}
