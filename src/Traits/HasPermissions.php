<?php

namespace Oricodes\TenantPermission\Traits;

use BackedEnum;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Oricodes\TenantPermission\Contracts\Permission;
use Oricodes\TenantPermission\Contracts\Role;
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
use function get_class;

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

			$teams = app(PermissionRegistrar::class)->teams;
			app(PermissionRegistrar::class)->teams = false;
			if (!is_a($model, Permission::class)) {
				$model->permissions()->detach();
			}
			if (is_a($model, Role::class)) {
				$model->users()->detach();
			}
			app(PermissionRegistrar::class)->teams = $teams;
		});
	}

	/**
	 * A model may have multiple direct permissions.
	 */
	public function permissions() : BelongsToMany {
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
	 * whether indirectly by role or by direct permission.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 */
	public function scopeWithoutPermission(Builder $query, $permissions)
	: Builder {
		return $this->scopePermission($query, $permissions, true);
	}

	/**
	 * Scope the model query to certain permissions only.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 * @param bool $without
	 */
	public function scopePermission(Builder $query, $permissions, $without = false)
	: Builder {
		$permissions = $this->convertToPermissionModels($permissions);

		$permissionKey = (new ($this->getPermissionClass()))->getKeyName();
		$roleKey = (new (is_a($this, Role::class) ? static::class : $this->getRoleClass()))->getKeyName();

		$rolesWithPermissions = is_a($this, Role::class) ? [] : array_unique(
			array_reduce($permissions, fn($result, $permission) => array_merge($result, $permission->roles->all()), [])
		);

		return $query->where(fn(Builder $query) => $query
			->{!$without ? 'whereHas' : 'whereDoesntHave'}('permissions', fn(Builder $subQuery) => $subQuery
				->whereIn(config('tenant-permission.table_names.permissions') . ".$permissionKey", array_column($permissions, $permissionKey))
			)
			->when(count($rolesWithPermissions), fn($whenQuery) => $whenQuery
				->{!$without ? 'orWhereHas' : 'whereDoesntHave'}('roles', fn(Builder $subQuery) => $subQuery
					->whereIn(config('tenant-permission.table_names.roles') . ".$roleKey", array_column($rolesWithPermissions, $roleKey))
				)
			)
		);
	}

	/**
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 *
	 * @throws PermissionDoesNotExist
	 */
	protected function convertToPermissionModels($permissions)
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
	public function hasAnyPermission(...$permissions)
	: bool {
		$permissions = collect($permissions)->flatten();

		foreach ($permissions as $permission) {
			if ($this->checkPermissionTo($permission)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * An alias to hasPermissionTo(), but avoids throwing an exception.
	 *
	 * @param string|int|Permission|BackedEnum $permission
	 * @param string|null $tenantName
	 */
	public function checkPermissionTo($permission, $tenantName = null)
	: bool {
		try {
			return $this->hasPermissionTo($permission, $tenantName);
		} catch (PermissionDoesNotExist $e) {
			return false;
		}
	}

	/**
	 * Determine if the model may perform the given permission.
	 *
	 * @param string|int|Permission|BackedEnum $permission
	 * @param string|null $tenantName
	 *
	 * @throws PermissionDoesNotExist
	 */
	public function hasPermissionTo($permission, $tenantName = null)
	: bool {
		if ($this->getWildcardClass()) {
			return $this->hasWildcardPermission($permission, $tenantName);
		}

		$permission = $this->filterPermission($permission, $tenantName);

		return $this->hasDirectPermission($permission) || $this->hasPermissionViaRole($permission);
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
	 * @param string|int|Permission|BackedEnum $permission
	 * @param string|null $tenantName
	 */
	protected function hasWildcardPermission($permission, $tenantName = null)
	: bool {
		$tenantName = $tenantName ?? $this->getDefaultTenantName();

		if ($permission instanceof BackedEnum) {
			$permission = $permission->value;
		}

		if (is_int($permission) || PermissionRegistrar::isUid($permission)) {
			$permission = $this->getPermissionClass()::findById($permission, $tenantName);
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
	 * @param string|int|Permission|BackedEnum $permission
	 * @return Permission
	 *
	 * @throws PermissionDoesNotExist
	 */
	public function filterPermission($permission)
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
	 * @param string|int|Permission|BackedEnum $permission
	 *
	 * @throws PermissionDoesNotExist
	 */
	public function hasDirectPermission($permission)
	: bool {
		$permission = $this->filterPermission($permission);

		return $this->permissions->contains($permission->getKeyName(), $permission->getKey());
	}

	/**
	 * Determine if the model has, via roles, the given permission.
	 */
	protected function hasPermissionViaRole(Permission $permission)
	: bool {
		if (is_a($this, Role::class)) {
			return false;
		}

		return $this->hasRole($permission->roles);
	}

	/**
	 * Determine if the model has all of the given permissions.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum ...$permissions
	 */
	public function hasAllPermissions(...$permissions)
	: bool {
		$permissions = collect($permissions)->flatten();

		foreach ($permissions as $permission) {
			if (!$this->checkPermissionTo($permission)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Return all the permissions the model has, both directly and via roles.
	 */
	public function getAllPermissions()
	: Collection {
		/** @var Collection $permissions */
		$permissions = $this->permissions;

		if (method_exists($this, 'roles')) {
			$permissions = $permissions->merge($this->getPermissionsViaRoles());
		}

		return $permissions->sort()->values();
	}

	/**
	 * Return all the permissions the model has via roles.
	 */
	public function getPermissionsViaRoles()
	: Collection {
		if (is_a($this, Role::class) || is_a($this, Permission::class)) {
			return collect();
		}

		return $this->loadMissing('roles', 'roles.permissions')
			->roles->flatMap(fn($role) => $role->permissions)
			->sort()->values();
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
			$this->permissions()->detach();
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
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 * @return Permission|Permission[]|Collection
	 * @throws ReflectionException
	 */
	protected function getStoredPermission($permissions)
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
	 * @throws ReflectionException
	 */
	protected function getTenantNames()
	: Collection {
		return Tenant::getNames($this);
	}

	/**
	 * @param Permission|Role $roleOrPermission
	 *
	 * @throws TenantDoesNotMatch
	 * @throws ReflectionException
	 */
	protected function ensureModelSharesTenant($roleOrPermission)
	: void {
		if (!$this->getTenantNames()->contains($roleOrPermission->tenant_name)) {
			throw TenantDoesNotMatch::create($roleOrPermission->tenant_name, $this->getTenantNames());
		}
	}

	/**
	 * Grant the given permission(s) to a role.
	 *
	 * @param string|int|array|Permission|Collection|BackedEnum $permissions
	 * @return $this
	 * @throws ReflectionException
	 */
	public function givePermissionTo($tenantName, ...$permissions)
	: static {
		$permissions = $this->collectPermissions($permissions);

		$model = $this->getModel();
		$currentPermissions = $this->permissions->map(fn($permission) => $permission->getKey())->toArray();

        $permissionsRelation = $this->permissions();

        $existingPermissions = $permissionsRelation
            ->where(function ($query) use ($tenantName) {
                $query->where('tenant_name', '=', $tenantName);
            })
            ->get();
/*
        if ($existingPermissions->isEmpty()) {
            echo "Aucune permission trouvée avec le tenant_name spécifié.";
            print_r($existingPermissions);
        } else {
            // $existingPermissions contient les permissions qui ne correspondent pas à la condition
            print_r($existingPermissions->pluck('pivot.tenant_name')->toArray());
            return json_encode($existingPermissions->toArray());
        }
        */

        $permissionsToAttach = array_diff($permissions, $existingPermissions->pluck('id')->toArray());

        print_r($permissionsToAttach);

        // Attachez uniquement les permissions qui ne sont pas déjà attachées
        if (!empty($permissionsToAttach)) {
            $this->permissions()->attach($permissionsToAttach, ['tenant_name' => $tenantName]);
        }

			$model->unsetRelation('permissions');

		if (is_a($this, Role::class)) {
			$this->forgetCachedPermissions();
		}

		$this->forgetWildcardPermissionIndex();

		return $this;
	}

	/**
	 * Forget the cached permissions.
	 */
	public function forgetCachedPermissions()
	: void {
		app(PermissionRegistrar::class)->forgetCachedPermissions();
	}

	public function forgetWildcardPermissionIndex()
	: void {
		app(PermissionRegistrar::class)->forgetWildcardPermissionIndex(
			is_a($this, Role::class) ? null : $this,
		);
	}

	/**
	 * Revoke the given permission(s).
	 *
	 * @param Permission|Permission[]|string|string[]|BackedEnum $permission
	 * @return $this
	 */
	public function revokePermissionTo($tenantName, $permission)
	: static {
		$this->permissions()
            ->wherePivot('tenant_name', $tenantName)
            ->detach($this->getStoredPermission($permission));

		if (is_a($this, Role::class)) {
			$this->forgetCachedPermissions();
		}

		$this->forgetWildcardPermissionIndex();

		$this->unsetRelation('permissions');

		return $this;
	}

	public function getPermissionNames()
	: Collection {
		return $this->permissions->pluck('name');
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
}
