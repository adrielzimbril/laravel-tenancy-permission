<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;

class TenantPermissionMiddleware {
	/**
	 * Specify the permission and tenant for the middleware.
	 *
	 * @param string $tenant
	 * @param array|string $permission
	 * @return string
	 */
	public static function using(string $tenant, array | string $permission)
	: string {
		$permissionString = is_string($permission) ? $permission : implode('|', $permission);
		$args = "$tenant,$permissionString";

		return static::class . ':' . $args;
	}

	public function handle($request, Closure $next, $tenant, $permission) {
		$user = tenant($tenant)->user ?? tenant()->user;

		if (!$user) {
			throw UnauthorizedException::notLoggedIn();
		}

		if (!method_exists($user, 'hasAnyPermission')) {
			throw UnauthorizedException::missingTraitHasPermissions($user);
		}

		$permissions = is_array($permission)
			? $permission
			: explode('|', $permission);

		if (!$user->canAny($tenant, $permissions)) {
			print_r($user . "\n\n\n" . $tenant . "\n" . $permission);
			throw UnauthorizedException::forPermissions($permissions);
		}

		return $next($request);
	}
}
