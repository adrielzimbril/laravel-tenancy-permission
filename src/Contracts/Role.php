<?php

namespace Oricodes\TenantPermission\Contracts;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Oricodes\TenantPermission\Exceptions\RoleDoesNotExist;

/**
 * @property int|string $id
 * @property string $name
 * @property string|null $tenant_name
 *
 * @mixin \Oricodes\TenantPermission\Models\Role
 */
interface Role
{
    /**
     * Find a role by its name and tenant name.
     *
     *
     * @throws RoleDoesNotExist
     */
    public static function findByName(string $name, ?string $tenantName): self;

    /**
     * Find a role by its id and tenant name.
     *
     *
     * @throws RoleDoesNotExist
     */
    public static function findById(int|string $id, ?string $tenantName): self;

    /**
     * Find or create a role by its name and tenant name.
     */
    public static function findOrCreate(string $name, ?string $tenantName): self;

    /**
     * A role may be given various permissions.
     */
    public function permissions(): BelongsToMany;

    /**
     * Determine if the user may perform the given permission.
     *
     * @param  string|Permission $permission
     */
    public function hasPermissionTo($permission, ?string $tenantName): bool;
}
