<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;

class TenantPermissionMiddleware {
	/**
	 * Specify the permission and tenant for the middleware.
	 *
	 * @param array|string $permission
	 * @param string|null $tenant
	 * @return string
	 */
	public static function using(array | string $permission, string $tenant = null)
	: string {
		$permissionString = is_string($permission) ? $permission : implode('|', $permission);
		$args = is_null($tenant) ? $permissionString : "$permissionString,$tenant";

		return static::class . ':' . $args;
	}

	public function handle($request, Closure $next, $permission, $tenant = null) {
		$user = $tenant ? tenant($tenant)->user : tenant()->user;

		if (!$user) {
			throw UnauthorizedException::notLoggedIn();
		}

		if (!method_exists($user, 'hasAnyPermission')) {
			throw UnauthorizedException::missingTraitHasPermissions($user);
		}

		$permissions = is_array($permission)
			? $permission
			: explode('|', $permission);

		if (!$user->canAny($permissions)) {
			throw UnauthorizedException::forPermissions($permissions);
		}

		return $next($request);
	}
}
