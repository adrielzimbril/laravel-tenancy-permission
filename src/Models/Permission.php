<?php

namespace Oricodes\TenantPermission\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Carbon;
use Oricodes\TenantPermission\Contracts\Permission as PermissionContract;
use Oricodes\TenantPermission\Exceptions\PermissionAlreadyExists;
use Oricodes\TenantPermission\Exceptions\PermissionDoesNotExist;
use Oricodes\TenantPermission\PermissionRegistrar;
use Oricodes\TenantPermission\Tenant;
use Oricodes\TenantPermission\Traits\HasRoles;
use Oricodes\TenantPermission\Traits\RefreshesPermissionCache;

/**
 * @property ?Carbon $created_at
 * @property ?Carbon $updated_at
 */
class Permission extends Model implements PermissionContract {
	use HasRoles;
	use RefreshesPermissionCache;

	protected $tenanted = [];

	protected $fillable = [
		'tenant_name',
	];

	public function __construct(array $attributes = []) {
		$attributes['tenant_name'] = $attributes['tenant_name'] ?? tenant()->id;

		parent::__construct($attributes);

		$this->guarded[] = $this->primaryKey;
		$this->table = config('tenant-permission.table_names.permissions') ?: parent::getTable();
	}

	/**
	 * Find a permission by its name (and optionally tenantName).
	 *
	 * @param string $name
	 * @param string|null $tenantName
	 * @return PermissionContract
	 *
	 */
	public static function findByName(string $name, ?string $tenantName = null)
	: PermissionContract {
		$tenantName = $tenantName ?? Tenant::getDefaultName();
		$permission = static::getPermission(['name' => $name, 'tenant_name' => $tenantName]);
		if (!$permission) {
			throw PermissionDoesNotExist::create($name, $tenantName);
		}

		return $permission;
	}

	/**
	 * Get the current cached first permission.
	 *
	 * @param array $params
	 * @return PermissionContract|null
	 */
	protected static function getPermission(array $params = [])
	: ?PermissionContract {
		/** @var PermissionContract|null */
		return static::getPermissions($params, true)->first();
	}

	/**
	 * Get the current cached permissions.
	 */
	protected static function getPermissions(array $params = [], bool $onlyOne = false)
	: Collection {
		return app(PermissionRegistrar::class)
			->setPermissionClass(static::class)
			->getPermissions($params, $onlyOne);
	}

	/**
	 * @return Builder|Model
	 *
	 * @throws PermissionAlreadyExists
	 */
	public static function create(array $attributes = [])
	: Model | Builder {
		$attributes['tenant_name'] = $attributes['tenant_name'] ?? Tenant::getDefaultName();

		$permission = static::getPermission(['name'        => $attributes['name'],
		                                     'tenant_name' => $attributes['tenant_name']
		]);

		if ($permission) {
			throw PermissionAlreadyExists::create($attributes['name'], $attributes['tenant_name']);
		}

		return static::query()->create($attributes);
	}

	/**
	 * Find a permission by its id (and optionally tenantName).
	 *
	 * @return PermissionContract|Permission
	 *
	 * @throws PermissionDoesNotExist
	 */
	public static function findById(int | string $id, ?string $tenantName = null)
	: PermissionContract {
		$tenantName = $tenantName ?? Tenant::getDefaultName();
		$permission = static::getPermission([(new static)->getKeyName() => $id, 'tenant_name' => $tenantName]);

		if (!$permission) {
			throw PermissionDoesNotExist::withId($id, $tenantName);
		}

		return $permission;
	}

	/**
	 * Find or create permission by its name (and optionally tenantName).
	 *
	 * @return PermissionContract
	 */
	public static function findOrCreate(string $name, ?string $tenantName = null)
	: PermissionContract {
		$tenantName = $tenantName ?? Tenant::getDefaultName();
		$permission = static::getPermission(['name' => $name, 'tenant_name' => $tenantName]);

		if (!$permission) {
			return static::query()->create(['name' => $name, 'tenant_name' => $tenantName]);
		}

		return $permission;
	}

	/**
	 * A permission can be applied to roles.
	 */
	public function roles()
	: BelongsToMany {
		return $this->belongsToMany(
			config('tenant-permission.models.role'),
			config('tenant-permission.table_names.role_has_permissions'),
			app(PermissionRegistrar::class)->pivotPermission,
			app(PermissionRegistrar::class)->pivotRole
		);
	}

	/**
	 * A permission belongs to some users of the model associated with its tenant.
	 */
	public function users()
	: BelongsToMany {
		return $this->morphedByMany(
			getModelForTenant(),
			'model',
			config('tenant-permission.table_names.model_has_permissions'),
			app(PermissionRegistrar::class)->pivotPermission,
			config('tenant-permission.column_names.model_morph_key')
		);
	}
}
