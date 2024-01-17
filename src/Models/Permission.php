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
use Oricodes\TenantPermission\Traits\RefreshesPermissionCache;
use Stancl\Tenancy\Database\Concerns\CentralConnection;

/**
 * @property ?Carbon $created_at
 * @property ?Carbon $updated_at
 */
class Permission extends Model implements PermissionContract {
	use RefreshesPermissionCache;
	use CentralConnection;

	protected $tenanted = [];

	protected $fillable = [
		'name',
		'tenant_name',
	];

	public function __construct(array $attributes = []) {
		$attributes['tenant_name'] = $attributes['tenant_name'] ?? tenant()->id;

		parent::__construct($attributes);

		$this->guarded[] = $this->primaryKey;
		$this->table = config('tenant-permission.table_names.permissions') ?: parent::getTable();
	}

	/**
	 * Find a permission by its name.
	 *
	 * @param string $name
	 * @return PermissionContract
	 *
	 */
	public static function findByName(string $name)
	: PermissionContract {
		$permission = static::getPermission(['name' => $name]);
		if (!$permission) {
			throw PermissionDoesNotExist::create($name);
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
	 * @param array $attributes
	 * @return Builder|Model
	 *
	 */
	public static function create(array $attributes = [])
	: Model | Builder {
		$attributes['tenant_name'] = $attributes['tenant_name'] ?? Tenant::getDefaultName();

		$permission = static::getPermission(['name' => $attributes['name']
		]);

		if ($permission) {
			throw PermissionAlreadyExists::create($attributes['name']);
		}

		return static::query()->create($attributes);
	}

	/**
	 * Find a permission by its id (and optionally tenantName).
	 *
	 * @param int|string $id
	 * @return PermissionContract
	 */
	public static function findById(int | string $id)
	: PermissionContract {
		$tenantName = $tenantName ?? Tenant::getDefaultName();
		$permission = static::getPermission([(new static)->getKeyName() => $id]);

		if (!$permission) {
			throw PermissionDoesNotExist::withId($id);
		}

		return $permission;
	}

	/**
	 * Find or create permission by its name (and optionally tenantName).
	 *
	 * @param string $name
	 * @return PermissionContract
	 */
	public static function findOrCreate(string $name)
	: PermissionContract {
		$tenantName = $tenantName ?? Tenant::getDefaultName();
		$permission = static::getPermission(['name' => $name]);

		if (!$permission) {
			return static::query()->create(['name' => $name]);
		}

		return $permission;
	}

	/**
	 * A permission can be applied to tenant.
	 */
	public function tenant()
	: BelongsToMany {
		return $this->belongsToMany(
			getModelForTenant(),
			config('tenant-permission.table_names.model_has_permissions'),
			app(PermissionRegistrar::class)->pivotPermission,
			'tenant_name'
		);
	}

	/**
	 * A permission belongs to some users of the model associated with its tenant.
	 */
	public function users()
	: BelongsToMany {
		return $this->morphedByMany(
			getModelForUser(),
			'model',
			config('tenant-permission.table_names.model_has_permissions'),
			app(PermissionRegistrar::class)->pivotPermission,
			config('tenant-permission.column_names.model_morph_key')
		);
	}
}
