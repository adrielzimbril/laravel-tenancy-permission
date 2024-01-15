<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;
use Oricodes\TenantPermission\Guard;

class RoleOrPermissionMiddleware
{
    /**
     * Specify the role or permission and guard for the middleware.
     *
     * @param  array|string  $roleOrPermission
     * @param  string|null  $tenant
     * @return string
     */
    public static function using($roleOrPermission, $tenant = null)
    {
        $roleOrPermissionString = is_string($roleOrPermission) ? $roleOrPermission : implode('|', $roleOrPermission);
        $args = is_null($tenant) ? $roleOrPermissionString : "$roleOrPermissionString,$tenant";

        return static::class.':'.$args;
    }

    public function handle($request, Closure $next, $roleOrPermission, $tenant = null)
    {
        $authGuard = Auth::guard($tenant);

        $user = $authGuard->user();

        // For machine-to-machine Passport clients
        if (! $user && $request->bearerToken() && config('permission.use_passport_client_credentials')) {
            $user = Guard::getPassportClient($tenant);
        }

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
