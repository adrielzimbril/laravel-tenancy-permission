<?php

namespace Oricodes\TenantPermission\Exceptions;

use Illuminate\Contracts\Auth\Access\Authorizable;
use Symfony\Component\HttpKernel\Exception\HttpException;

class UnauthorizedException extends HttpException {
	private $requiredPermissions = [];

	public static function forPermissions(array $permissions)
	: self {
		$message = 'User does not have the right permissions.';

		if (config('tenant-permission.display_permission_in_exception')) {
			$message .= ' Necessary permissions are ' . implode(', ', $permissions);
		}

		$exception = new static(403, $message, null, []);
		$exception->requiredPermissions = $permissions;

		return $exception;
	}

	public static function missingTraitHasPermissions(Authorizable $user)
	: self {
		$class = get_class($user);

		return new static(403, "Authorizable class `{$class}` must use Oricodes\TenantPermission\Traits\HasPermissions trait.", null, []);
	}

	public static function notLoggedIn()
	: self {
		return new static(403, 'User is not logged in.', null, []);
	}

	public function getRequiredPermissions()
	: array {
		return $this->requiredPermissions;
	}
}
