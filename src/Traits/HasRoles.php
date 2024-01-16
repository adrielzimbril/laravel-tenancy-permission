<?php

namespace Oricodes\TenantPermission\Traits;

use BackedEnum;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Oricodes\TenantPermission\Contracts\Permission;
use Oricodes\TenantPermission\Contracts\Role;
use Oricodes\TenantPermission\PermissionRegistrar;
use TypeError;
use function array_column;
use function get_class;

trait HasRoles {
	use HasPermissions;

	private ?string $roleClass = null;

	public static function bootHasRoles() {
		static::deleting(function ($model) {
			if (method_exists($model, 'isForceDeleting') && !$model->isForceDeleting()) {
				return;
			}

			$teams = app(PermissionRegistrar::class)->teams;
			app(PermissionRegistrar::class)->teams = false;
			$model->roles()->detach();
			if (is_a($model, Permission::class)) {
				$model->users()->detach();
			}
			app(PermissionRegistrar::class)->teams = $teams;
		});
	}

	/**
	 * A model may have multiple roles.
	 */
	public function roles()
	: BelongsToMany {
		$relation = $this->morphToMany(
			config('tenant-permission.models.role'),
			'model',
			config('tenant-permission.table_names.model_has_roles'),
			config('tenant-permission.column_names.model_morph_key'),
			app(PermissionRegistrar::class)->pivotRole
		);

		if (!app(PermissionRegistrar::class)->teams) {
			return $relation;
		}

		$teamField = config('tenant-permission.table_names.roles') . '.' . app(PermissionRegistrar::class)->teamsKey;

		return $relation->wherePivot(app(PermissionRegistrar::class)->teamsKey, getPermissionsTeamId())
			->where(fn($q) => $q->whereNull($teamField)->orWhere($teamField, getPermissionsTeamId()));
	}

	/**
	 * Scope the model query to only those without certain roles.
	 *
	 * @param string|int|array|Role|Collection|BackedEnum $roles
	 * @param string $tenant
	 */
	public function scopeWithoutRole(Builder $query, $roles, $tenant = null)
	: Builder {
		return $this->scopeRole($query, $roles, $tenant, true);
	}

	/**
	 * Scope the model query to certain roles only.
	 *
	 * @param string|int|array|Role|Collection|BackedEnum $roles
	 * @param string $tenant
	 * @param bool $without
	 */
	public function scopeRole(Builder $query, $roles, $tenant = null, $without = false)
	: Builder {
		if ($roles instanceof Collection) {
			$roles = $roles->all();
		}

		$roles = array_map(function ($role) use ($tenant) {
			if ($role instanceof Role) {
				return $role;
			}

			if ($role instanceof BackedEnum) {
				$role = $role->value;
			}

			$method = is_int($role) || PermissionRegistrar::isUid($role) ? 'findById' : 'findByName';

			return $this->getRoleClass()::{$method}($role, $tenant ?: $this->getDefaultTenantName());
		}, Arr::wrap($roles));

		$key = (new ($this->getRoleClass()))->getKeyName();

		return $query->{!$without ? 'whereHas' : 'whereDoesntHave'}('roles', fn(Builder $subQuery) => $subQuery
			->whereIn(config('tenant-permission.table_names.roles') . ".$key", array_column($roles, $key))
		);
	}

	public function getRoleClass()
	: string {
		if (!$this->roleClass) {
			$this->roleClass = app(PermissionRegistrar::class)->getRoleClass();
		}

		return $this->roleClass;
	}

	/**
	 * Revoke the given role from the model.
	 *
	 * @param string|int|Role|BackedEnum $role
	 */
	public function removeRole($role) {
		$this->roles()->detach($this->getStoredRole($role));

		$this->unsetRelation('roles');

		if (is_a($this, Permission::class)) {
			$this->forgetCachedPermissions();
		}

		return $this;
	}

	protected function getStoredRole($role)
	: Role {
		if ($role instanceof BackedEnum) {
			$role = $role->value;
		}

		if (is_int($role) || PermissionRegistrar::isUid($role)) {
			return $this->getRoleClass()::findById($role, $this->getDefaultTenantName());
		}

		if (is_string($role)) {
			return $this->getRoleClass()::findByName($role, $this->getDefaultTenantName());
		}

		return $role;
	}

	/**
	 * Remove all current roles and set the given ones.
	 *
	 * @param string|int|array|Role|Collection|BackedEnum ...$roles
	 * @return $this
	 */
	public function syncRoles(...$roles)
	: static {
		if ($this->getModel()->exists) {
			$this->collectRoles($roles);
			$this->roles()->detach();
			$this->setRelation('roles', collect());
		}

		return $this->assignRole($roles);
	}

	/**
	 * Returns roles ids as array keys
	 *
	 * @param string|int|array|Role|Collection|BackedEnum $roles
	 */
	private function collectRoles(...$roles)
	: array {
		return collect($roles)
			->flatten()
			->reduce(function ($array, $role) {
				if (empty($role)) {
					return $array;
				}

				$role = $this->getStoredRole($role);
				if (!$role instanceof Role) {
					return $array;
				}

				if (!in_array($role->getKey(), $array)) {
					$this->ensureModelSharesTenant($role);
					$array[] = $role->getKey();
				}

				return $array;
			}, []);
	}

	/**
	 * Assign the given role to the model.
	 *
	 * @param string|int|array|Role|Collection|BackedEnum ...$roles
	 * @return $this
	 */
	public function assignRole(...$roles)
	: static {
		$roles = $this->collectRoles($roles);

		$model = $this->getModel();
		$teamPivot = app(PermissionRegistrar::class)->teams && !is_a($this, Permission::class) ?
			[app(PermissionRegistrar::class)->teamsKey => getPermissionsTeamId()] : [];

		if ($model->exists) {
			$currentRoles = $this->roles->map(fn($role) => $role->getKey())->toArray();

			$this->roles()->attach(array_diff($roles, $currentRoles), $teamPivot);
			$model->unsetRelation('roles');
		} else {
			$class = get_class($model);

			$class::saved(
				function ($object) use ($roles, $model, $teamPivot) {
					if ($model->getKey() != $object->getKey()) {
						return;
					}
					$model->roles()->attach($roles, $teamPivot);
					$model->unsetRelation('roles');
				}
			);
		}

		if (is_a($this, Permission::class)) {
			$this->forgetCachedPermissions();
		}

		return $this;
	}

	/**
	 * Determine if the model has any of the given role(s).
	 *
	 * Alias to hasRole() but without Tenant controls
	 *
	 * @param string|int|array|Role|Collection|BackedEnum $roles
	 */
	public function hasAnyRole(...$roles)
	: bool {
		return $this->hasRole($roles);
	}

	/**
	 * Determine if the model has (one of) the given role(s).
	 *
	 * @param string|int|array|Role|Collection|BackedEnum $roles
	 */
	public function hasRole($roles, ?string $tenant = null)
	: bool {
		$this->loadMissing('roles');

		if (is_string($roles) && str_contains($roles, '|')) {
			$roles = $this->convertPipeToArray($roles);
		}

		if ($roles instanceof BackedEnum) {
			$roles = $roles->value;
		}

		if (is_int($roles) || PermissionRegistrar::isUid($roles)) {
			$key = (new ($this->getRoleClass()))->getKeyName();

			return $tenant
				? $this->roles->where('tenant_name', $tenant)->contains($key, $roles)
				: $this->roles->contains($key, $roles);
		}

		if (is_string($roles)) {
			return $tenant
				? $this->roles->where('tenant_name', $tenant)->contains('name', $roles)
				: $this->roles->contains('name', $roles);
		}

		if ($roles instanceof Role) {
			return $this->roles->contains($roles->getKeyName(), $roles->getKey());
		}

		if (is_array($roles)) {
			foreach ($roles as $role) {
				if ($this->hasRole($role, $tenant)) {
					return true;
				}
			}

			return false;
		}

		if ($roles instanceof Collection) {
			return $roles->intersect($tenant ? $this->roles->where('tenant_name', $tenant) : $this->roles)->isNotEmpty();
		}

		throw new TypeError('Unsupported type for $roles parameter to hasRole().');
	}

	protected function convertPipeToArray(string $pipeString) {
		$pipeString = trim($pipeString);

		if (strlen($pipeString) <= 2) {
			return [str_replace('|', '', $pipeString)];
		}

		$quoteCharacter = substr($pipeString, 0, 1);
		$endCharacter = substr($quoteCharacter, -1, 1);

		if ($quoteCharacter !== $endCharacter) {
			return explode('|', $pipeString);
		}

		if (!in_array($quoteCharacter, ["'", '"'])) {
			return explode('|', $pipeString);
		}

		return explode('|', trim($pipeString, $quoteCharacter));
	}

	/**
	 * Determine if the model has exactly all of the given role(s).
	 *
	 * @param string|array|Role|Collection $roles
	 */
	public function hasExactRoles($roles, ?string $tenant = null)
	: bool {
		$this->loadMissing('roles');

		if (is_string($roles) && str_contains($roles, '|')) {
			$roles = $this->convertPipeToArray($roles);
		}

		if (is_string($roles)) {
			$roles = [$roles];
		}

		if ($roles instanceof Role) {
			$roles = [$roles->name];
		}

		$roles = collect()->make($roles)->map(fn($role) => $role instanceof Role ? $role->name : $role
		);

		return $this->roles->count() == $roles->count() && $this->hasAllRoles($roles, $tenant);
	}

	/**
	 * Determine if the model has all of the given role(s).
	 *
	 * @param string|array|Role|Collection|BackedEnum $roles
	 */
	public function hasAllRoles($roles, ?string $tenant = null)
	: bool {
		$this->loadMissing('roles');

		if ($roles instanceof BackedEnum) {
			$roles = $roles->value;
		}

		if (is_string($roles) && str_contains($roles, '|')) {
			$roles = $this->convertPipeToArray($roles);
		}

		if (is_string($roles)) {
			return $tenant
				? $this->roles->where('tenant_name', $tenant)->contains('name', $roles)
				: $this->roles->contains('name', $roles);
		}

		if ($roles instanceof Role) {
			return $this->roles->contains($roles->getKeyName(), $roles->getKey());
		}

		$roles = collect()->make($roles)->map(function ($role) {
			if ($role instanceof BackedEnum) {
				return $role->value;
			}

			return $role instanceof Role ? $role->name : $role;
		});

		return $roles->intersect(
				$tenant
					? $this->roles->where('tenant_name', $tenant)->pluck('name')
					: $this->getRoleNames()
			) == $roles;
	}

	public function getRoleNames()
	: Collection {
		$this->loadMissing('roles');

		return $this->roles->pluck('name');
	}

	/**
	 * Return all permissions directly coupled to the model.
	 */
	public function getDirectPermissions()
	: Collection {
		return $this->permissions;
	}
}
