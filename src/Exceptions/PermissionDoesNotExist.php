<?php

namespace Oricodes\TenantPermission\Exceptions;

use InvalidArgumentException;

class PermissionDoesNotExist extends InvalidArgumentException {
	public static function create(string $permissionName)
	: static {
		return new static("There is no permission named `{$permissionName}`.");
	}

	/**
	 * @param int|string $permissionId
	 * @return static
	 */
	public static function withId(int | string $permissionId)
	: static {
		return new static("There is no [permission] with ID `{$permissionId}`.");
	}
}
