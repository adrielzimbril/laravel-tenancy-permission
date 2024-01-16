<?php

namespace Oricodes\TenantPermission\Models;

use BackedEnum;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Carbon;
use Oricodes\TenantPermission\Contracts\Role as RoleContract;
use Oricodes\TenantPermission\Exceptions\PermissionDoesNotExist;
use Oricodes\TenantPermission\Exceptions\RoleAlreadyExists;
use Oricodes\TenantPermission\Exceptions\RoleDoesNotExist;
use Oricodes\TenantPermission\Exceptions\TenantDoesNotMatch;
use Oricodes\TenantPermission\PermissionRegistrar;
use Oricodes\TenantPermission\Tenant;
use Oricodes\TenantPermission\Traits\HasPermissions;
use Oricodes\TenantPermission\Traits\RefreshesPermissionCache;
use ReflectionException;

/**
 * @property ?Carbon $created_at
 * @property ?Carbon $updated_at
 */
class Role extends Model implements RoleContract
{
    use HasPermissions;
    use RefreshesPermissionCache;

    protected $tenanted = [];

    public function __construct(array $attributes = [])
    {
        $attributes['tenant_name'] = $attributes['tenant_name'] ?? tenant()->id;

        parent::__construct($attributes);

        $this->guarded[] = $this->primaryKey;
        $this->table = config('tenant-permission.table_names.roles') ?: parent::getTable();
    }

    /**
     * Find a role by its name and tenant name.
     *
     * @return RoleContract|Role
     *
     * @throws RoleDoesNotExist
     */
    public static function findByName(string $name, ?string $tenantName = null): RoleContract
    {
        $tenantName = $tenantName ?? Tenant::getDefaultName();

        $role = static::findByParam(['name' => $name, 'tenant_name' => $tenantName]);

        if (! $role) {
            throw RoleDoesNotExist::named($name, $tenantName);
        }

        return $role;
    }

    /**
     * Finds a role based on an array of parameters.
     *
     */
    protected static function findByParam(array $params = []): ?RoleContract
    {
        $query = static::query();

        if (app(PermissionRegistrar::class)->teams) {
            $teamsKey = app(PermissionRegistrar::class)->teamsKey;

            $query->where(fn ($q) => $q->whereNull($teamsKey)
                ->orWhere($teamsKey, $params[$teamsKey] ?? getPermissionsTeamId())
            );
            unset($params[$teamsKey]);
        }

        foreach ($params as $key => $value) {
            $query->where($key, $value);
        }

        return $query->first();
    }

	/**
	 * Find a role by its id (and optionally tenantName).
	 *
	 * @param int|string $id
	 * @param string|null $tenantName
	 * @return RoleContract
	 * @throws ReflectionException
	 */
    public static function findById(int|string $id, ?string $tenantName = null): RoleContract
    {
        $tenantName = $tenantName ?? Tenant::getDefaultName();

        $role = static::findByParam([(new static())->getKeyName() => $id, 'tenant_name' => $tenantName]);

        if (! $role) {
            throw RoleDoesNotExist::withId($id, $tenantName);
        }

        return $role;
    }

	/**
	 * Find or create role by its name (and optionally tenantName).
	 *
	 * @param string $name
	 * @param string|null $tenantName
	 * @return RoleContract
	 * @throws ReflectionException
	 */
    public static function findOrCreate(string $name, ?string $tenantName = null): RoleContract
    {
        $tenantName = $tenantName ?? Tenant::getDefaultName();

        $role = static::findByParam(['name' => $name, 'tenant_name' => $tenantName]);

        if (! $role) {
            return static::query()->create(['name' => $name, 'tenant_name' => $tenantName] + (app(PermissionRegistrar::class)->teams ? [app(PermissionRegistrar::class)->teamsKey => getPermissionsTeamId()] : []));
        }

        return $role;
    }

    /**
     * @return RoleContract|Role
     *
     * @throws RoleAlreadyExists
     */
    public static function create(array $attributes = [])
    : Role | RoleContract {
        $attributes['tenant_name'] = $attributes['tenant_name'] ?? Tenant::getDefaultName();

        $params = ['name' => $attributes['name'], 'tenant_name' => $attributes['tenant_name']];
        if (app(PermissionRegistrar::class)->teams) {
            $teamsKey = app(PermissionRegistrar::class)->teamsKey;

            if (array_key_exists($teamsKey, $attributes)) {
                $params[$teamsKey] = $attributes[$teamsKey];
            } else {
                $attributes[$teamsKey] = getPermissionsTeamId();
            }
        }
        if (static::findByParam($params)) {
            throw RoleAlreadyExists::create($attributes['name'], $attributes['tenant_name']);
        }

        return static::query()->create($attributes);
    }

    /**
     * A role may be given various permissions.
     */
    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(
            config('tenant-permission.models.permission'),
            config('tenant-permission.table_names.role_has_permissions'),
            app(PermissionRegistrar::class)->pivotRole,
            app(PermissionRegistrar::class)->pivotPermission
        );
    }

    /**
     * A role belongs to some users of the model associated with its tenant.
     */
    public function users(): BelongsToMany
    {
	    $tenantId = '';

		$r = tenancy()->getTenant($tenantId)->make(TenantUser::class);

        return $this->morphedByMany(
            getModelForTenant(),
            'model',
            config('tenant-permission.table_names.model_has_roles'),
            app(PermissionRegistrar::class)->pivotRole,
            config('tenant-permission.column_names.model_morph_key')
        );
    }

    /**
     * Determine if the role may perform the given permission.
     *
     * @param  string|int|Permission|BackedEnum  $permission
     *
     * @throws PermissionDoesNotExist|TenantDoesNotMatch
     */
    public function hasPermissionTo($permission, ?string $tenantName = null): bool
    {
        if ($this->getWildcardClass()) {
            return $this->hasWildcardPermission($permission, $tenantName);
        }

        $permission = $this->filterPermission($permission, $tenantName);

        if (! $this->getTenantNames()->contains($permission->tenant_name)) {
            throw TenantDoesNotMatch::create($permission->tenant_name, $tenantName ?? $this->getTenantNames());
        }

        return $this->permissions->contains($permission->getKeyName(), $permission->getKey());
    }
}
