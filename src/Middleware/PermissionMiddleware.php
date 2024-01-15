<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;
use Oricodes\TenantPermission\Guard;

class PermissionMiddleware
{
    /**
     * Specify the permission and guard for the middleware.
     *
     * @param  array|string  $permission
     * @param  string|null  $tenant
     * @return string
     */
    public static function using($permission, $tenant = null)
    {
        $permissionString = is_string($permission) ? $permission : implode('|', $permission);
        $args = is_null($tenant) ? $permissionString : "$permissionString,$tenant";

        return static::class.':'.$args;
    }

    public function handle($request, Closure $next, $permission, $tenant = null)
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

        if (! method_exists($user, 'hasAnyPermission')) {
            throw UnauthorizedException::missingTraitHasRoles($user);
        }

        $permissions = is_array($permission)
            ? $permission
            : explode('|', $permission);

        if (! $user->canAny($permissions)) {
            throw UnauthorizedException::forPermissions($permissions);
        }

        return $next($request);
    }
}
