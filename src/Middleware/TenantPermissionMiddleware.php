<?php

namespace Oricodes\TenantPermission\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Oricodes\TenantPermission\Exceptions\UnauthorizedException;

class TenantPermissionMiddleware {
	/**
	 * Specify the permission and tenant for the middleware.
	 *
	 * @param $request
	 * @param Closure $next
	 * @param array|string $permission
	 * @return string
	 */
	public function handle(Request $request, Closure $next, array | string $permission)
	: string {
		$tenant = tenant()->id;
		$user = Auth::guard('tenant_user')->user();

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
			throw UnauthorizedException::forPermissions($permissions);
		}

		return $next($request);
	}
}
