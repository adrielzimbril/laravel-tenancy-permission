<?php

namespace Oricodes\TenantPermission\Traits;

use BackedEnum;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Oricodes\TenantPermission\Contracts\Permission;
use Oricodes\TenantPermission\Contracts\Wildcard;
use Oricodes\TenantPermission\Exceptions\PermissionDoesNotExist;
use Oricodes\TenantPermission\Exceptions\TenantDoesNotMatch;
use Oricodes\TenantPermission\Exceptions\WildcardPermissionInvalidArgument;
use Oricodes\TenantPermission\Exceptions\WildcardPermissionNotImplementsContract;
use Oricodes\TenantPermission\PermissionRegistrar;
use Oricodes\TenantPermission\Tenant;
use Oricodes\TenantPermission\WildcardPermission;
use ReflectionException;
use function array_column;

trait HasPermissions {
	private ?string $permissionClass = null;

	private ?string $wildcardClass = null;

	private array $wildcardPermissionsIndex;

	public static function bootHasPermissions()
	: void {
		static::deleting(function ($model) {
			if (method_exists($model, 'isForceDeleting') && !$model->isForceDeleting()) {
				return;
			}

			if (!is_a($model, Permission::class)) {
				$model->permissions()->detach();
			}
		});
	}

	/**
	 * A model may have multiple direct permissions.
	 */
	public function permissions()
	: BelongsToMany {
		$relation = $this->morphToMany(
			config('tenant-permission.models.permission'),
			'model',
			config('tenant-permission.table_names.model_has_permissions'),
			config('tenant-permission.column_names.model_morph_key'),
			app(PermissionRegistrar::class)->pivotPermission
		)->withPivot('tenant_name');

		return $relation;
	}

	/**
	 * Scope the model query to only those without certain permissions,
	 * whether indirectly by direct permission.
	 *
	 * @param Builder $query
	 * @param BackedEnum|int|array|string|Collection|Permission $permissions
	 * @return Builder
	 */
	public function scopeWithoutPermission(Builder $query, BackedEnum | int | array | string | Collection | Permission $permissions)
	: Builder {
		return $this->scopePermission($query, $permissions, true);
	}

	/**
	 * Scope the model query to certain permissions only.
	 *
	 * @param Builder $query
	 * @param BackedEnum|int|array|string|Collection|Permission $permissions
	 * @param bool $without
	 * @return Builder
	 */
	public function scopePermission(Builder $query, BackedEnum | int | array | string | Collection | Permission $permissions, bool $without = false)
	: Builder {
		$permissions = $this->convertToPermissionModels($permissions);

		$permissionKey = (new ($this->getPermissionClass()))->getKeyName();

		return $query->where(fn(Builder $query) => $query
			->{!$without ? 'whereHas' : 'whereDoesntHave'}('permissions', fn(Builder $subQuery) => $subQuery
				->whereIn(config('tenant-permission.table_names.permissions') . ".$permissionKey", array_column($permissions, $permissionKey))
			)
		);
	}

	/**
	 * @param BackedEnum|int|array|string|Collection|Permission $permissions
	 *
	 * @return array
	 */
	protected function convertToPermissionModels(BackedEnum | int | array | string | Collection | Permission $permissions)
	: array {
		if ($permissions instanceof Collection) {
			$permissions = $permissions->all();
		}

		return array_map(function ($permission) {
			if ($permission instanceof Permission) {
				return $permission;
			}

			if ($permission instanceof BackedEnum) {
				$permission = $permission->value;
			}

			$method = is_int($permission) || PermissionRegistrar::isUid($permission) ? 'findById' : 'findByName';

			return $this->getPermissionClass()::{$method}($permission, $this->getDefaultTenantName());
		}, Arr::wrap($permissions));
	}

	public function getPermissionClass()
	: string {
		if (!$this->permissionClass) {
			$this->permissionClass = app(PermissionRegistrar::class)->getPermissionClass();
		}

		return $this->permissionClass;
	}

	protected function getDefaultTenantName()
	: string {
		return tenant()->id;
	}

	/**
	 * Determine if the model has any of the given permissions.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum ...$permissions
	 */
	public function hasAnyPermission($tenantName, ...$permissions)
	: bool {
		$permissions = collect($permissions)->flatten();

		foreach ($permissions as $permission) {
			if ($this->checkPermissionTo($tenantName, $permission)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * An alias to hasPermissionTo(), but avoids throwing an exception.
	 *
	 * @param string|null $tenantName
	 * @param BackedEnum|int|string|Permission $permission
	 * @return bool
	 */
	public function checkPermissionTo(?string $tenantName, BackedEnum | int | string | Permission $permission)
	: bool {
		$tenantName = $tenantName ?? $this->getDefaultTenantName();

		try {
			return $this->hasPermissionTo($tenantName, $permission);
		} catch (PermissionDoesNotExist $e) {
			return false;
		}
	}

	/**
	 * Determine if the model may perform the given permission.
	 *
	 * @param string|null $tenantName
	 *
	 * @param BackedEnum|int|string|Permission $permission
	 * @return bool
	 */
	public function hasPermissionTo(?string $tenantName, BackedEnum | int | string | Permission $permission)
	: bool {
		if ($this->getWildcardClass()) {
			return $this->hasWildcardPermission($tenantName, $permission);
		}

		$permission = $this->filterPermission($permission);

		return $this->hasDirectPermission($permission);
	}

	public function getWildcardClass() {
		if (!is_null($this->wildcardClass)) {
			return $this->wildcardClass;
		}

		$this->wildcardClass = '';

		if (config('tenant-permission.enable_wildcard_permission')) {
			$this->wildcardClass = config('tenant-permission.wildcard_permission', WildcardPermission::class);

			if (!is_subclass_of($this->wildcardClass, Wildcard::class)) {
				throw WildcardPermissionNotImplementsContract::create();
			}
		}

		return $this->wildcardClass;
	}

	/**
	 * Validates a wildcard permission against all permissions of a user.
	 *
	 * @param string|null $tenantName
	 * @param mixed $permission
	 * @return bool
	 * @throws WildcardPermissionInvalidArgument
	 */
	protected function hasWildcardPermission(?string $tenantName, mixed $permission)
	: bool {
		$tenantName = $tenantName ?? $this->getDefaultTenantName();

		if ($permission instanceof BackedEnum) {
			$permission = $permission->value;
		}

		if (is_int($permission) || PermissionRegistrar::isUid($permission)) {
			$permission = $this->getPermissionClass()::findById($permission);
		}

		if ($permission instanceof Permission) {
			$permission = $permission->name;
		}

		if (!is_string($permission)) {
			throw WildcardPermissionInvalidArgument::create();
		}

		return app($this->getWildcardClass(), ['record' => $this])->implies(
			$permission,
			$tenantName,
			app(PermissionRegistrar::class)->getWildcardPermissionIndex($this),
		);
	}

	/**
	 * Find a permission.
	 *
	 * @param BackedEnum|int|string|Permission $permission
	 * @return Permission
	 *
	 * @throws PermissionDoesNotExist
	 */
	public function filterPermission(BackedEnum | int | string | Permission $permission)
	: Permission {
		if ($permission instanceof BackedEnum) {
			$permission = $permission->value;
		}

		if (is_int($permission) || PermissionRegistrar::isUid($permission)) {
			$permission = $this->getPermissionClass()::findById(
				$permission,
			);
		}

		if (is_string($permission)) {
			$permission = $this->getPermissionClass()::findByName(
				$permission,
			);
		}

		if (!$permission instanceof Permission) {
			throw new PermissionDoesNotExist;
		}

		return $permission;
	}

	/**
	 * Determine if the model has the given permission.
	 *
	 * @param BackedEnum|int|string|Permission $permission
	 *
	 * @return bool
	 */
	public function hasDirectPermission(BackedEnum | int | string | Permission $permission)
	: bool {
		$permission = $this->filterPermission($permission);

		return $this->permissions->contains($permission->getKeyName(), $permission->getKey());
	}


	/**
	 * Determine if the model has all of the given permissions.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum ...$permissions
	 */
	public function hasAllPermissions($tenantName, ...$permissions)
	: bool {
		$permissions = collect($permissions)->flatten();

		foreach ($permissions as $permission) {
			if (!$this->checkPermissionTo($tenantName, $permission)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Return all the permissions the model has directly.
	 */
	public function getAllPermissions()
	: Collection {
		/** @var Collection $permissions */
		$permissions = $this->permissions;

		return $permissions->sort()->values();
	}

	/**
	 * Remove all current permissions and set the given ones.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 * @return $this
	 * @throws ReflectionException
	 */
	public function syncPermissions($tenantName, ...$permissions)
	: static {
		if ($this->getModel()->exists) {
			$this->collectPermissions($permissions);
			$this->permissions()
				->wherePivot('tenant_name', $tenantName)
				->detach();
			$this->setRelation('permissions', collect());
		}

		return $this->givePermissionTo($permissions, $tenantName);
	}

	/**
	 * Returns permissions ids as array keys
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 * @throws ReflectionException
	 */
	private function collectPermissions(...$permissions)
	: array {
		return collect($permissions)
			->flatten()
			->reduce(function ($array, $permission) {
				if (empty($permission)) {
					return $array;
				}

				$permission = $this->getStoredPermission($permission);
				if (!$permission instanceof Permission) {
					return $array;
				}

				if (!in_array($permission->getKey(), $array)) {
					$array[] = $permission->getKey();
				}

				return $array;
			}, []);
	}

	/**
	 * @param BackedEnum|int|array|string|Collection|Permission $permissions
	 * @return BackedEnum|array|int|string|Collection|Permission
	 */
	protected function getStoredPermission(BackedEnum | int | array | string | Collection | Permission $permissions)
	: BackedEnum | array | int | string | Collection | Permission {
		if ($permissions instanceof BackedEnum) {
			$permissions = $permissions->value;
		}

		if (is_int($permissions) || PermissionRegistrar::isUid($permissions)) {
			return $this->getPermissionClass()::findById($permissions);
		}

		if (is_string($permissions)) {
			return $this->getPermissionClass()::findByName($permissions);
		}

		if (is_array($permissions)) {
			$permissions = array_map(function ($permission) {
				if ($permission instanceof BackedEnum) {
					return $permission->value;
				}

				return is_a($permission, Permission::class) ? $permission->name : $permission;
			}, $permissions);

			return $this->getPermissionClass()::whereIn('name', $permissions)
				->get();
		}

		return $permissions;
	}

	/**
	 * Grant the given permission(s) to a TenantName.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 * @return $this
	 * @throws ReflectionException
	 */
	public function givePermissionTo($tenantName, ...$permissions)
	: static {
		$permissions = $this->collectPermissions($permissions);

		$existingPermissions = $this->permissions()
			->where('tenant_name', $tenantName)
			->get();

		$permissionsToAttach = array_diff($permissions, $existingPermissions->pluck('id')->toArray());

		if (!empty($permissionsToAttach)) {
			$this->permissions()->attach($permissionsToAttach, ['tenant_name' => $tenantName]);
		}

		$this->getModel()->unsetRelation('permissions');

		$this->forgetWildcardPermissionIndex();

		return $this;
	}

	public function forgetWildcardPermissionIndex()
	: void {
		app(PermissionRegistrar::class)->forgetWildcardPermissionIndex($this);
	}

	/**
	 * Revoke the given permission(s).
	 *
	 * @param string|BackedEnum|Permission|Permission[]|string[] $permission
	 * @return $this
	 */
	public function revokePermissionTo($tenantName, array | string | Permission | BackedEnum $permission)
	: static {
		$this->permissions()
			->wherePivot('tenant_name', $tenantName)
			->detach($this->getStoredPermission($permission));

		$this->forgetWildcardPermissionIndex();

		$this->unsetRelation('permissions');

		return $this;
	}

	/**
	 * Forget the cached permissions.
	 */
	public function forgetCachedPermissions()
	: void {
		app(PermissionRegistrar::class)->forgetCachedPermissions();
	}

	public function getPermissionNames()
	: Collection {
		return $this->permissions->pluck('name');
	}

	public function getPermissionInfos()
	: Collection {
		return $this->permissions->pluck('name', 'pivot.tenant_name');
	}

	/**
	 * Check if the model has All of the requested Direct permissions.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum ...$permissions
	 */
	public function hasAllDirectPermissions(...$permissions)
	: bool {
		$permissions = collect($permissions)->flatten();

		foreach ($permissions as $permission) {
			if (!$this->hasDirectPermission($permission)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Check if the model has Any of the requested Direct permissions.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum ...$permissions
	 */
	public function hasAnyDirectPermission(...$permissions)
	: bool {
		$permissions = collect($permissions)->flatten();

		foreach ($permissions as $permission) {
			if ($this->hasDirectPermission($permission)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param Permission $permission
	 *
	 * @throws TenantDoesNotMatch
	 * @throws ReflectionException
	 */
	protected function ensureModelSharesTenant(Permission $permission)
	: void {
		if (!$this->getTenantNames()->contains($permission->tenant_name)) {
			throw TenantDoesNotMatch::create($permission->tenant_name, $this->getTenantNames());
		}
	}

	/**
	 * @throws ReflectionException
	 */
	protected function getTenantNames()
	: Collection {
		return Tenant::getNames($this);
	}
}
