<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;
use Oricodes\TenantPermission\Guard;

class RoleMiddleware
{
    /**
     * Specify the role and guard for the middleware.
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
        $authGuard = Auth::guard($tenant);

        $user = $authGuard->user();

        // For machine-to-machine Passport clients
        if (! $user && $request->bearerToken() && config('permission.use_passport_client_credentials')) {
            $user = Guard::getPassportClient($tenant);
        }

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
