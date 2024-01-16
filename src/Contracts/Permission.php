<?php

namespace Oricodes\TenantPermission\Contracts;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Oricodes\TenantPermission\Exceptions\PermissionDoesNotExist;

/**
 * @property int|string $id
 * @property string $name
 *
 * @mixin \Oricodes\TenantPermission\Models\Permission
 */
interface Permission {
	/**
	 * Find a permission by its name.
	 *
	 *
	 * @throws PermissionDoesNotExist
	 */
	public static function findByName(string $name)
	: self;

	/**
	 * Find a permission by its id.
	 *
	 *
	 * @throws PermissionDoesNotExist
	 */
	public static function findById(int | string $id)
	: self;

	/**
	 * Find or Create a permission by its name and tenant name.
	 */
	public static function findOrCreate(string $name)
	: self;

	/**
	 * A permission can be applied to roles.
	 */
	public function roles()
	: BelongsToMany;
}
