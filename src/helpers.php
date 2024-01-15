<?php

use Illuminate\Database\Eloquent\Model;
use Oricodes\TenantPermission\PermissionRegistrar;

if (! function_exists('getModelForTenant')) {
    /**
     * @return string|null
     */
    function getModelForTenant()
    : ?string {
        return App\Models\TenantUser::class;
    }
}

if (! function_exists('setPermissionsTeamId')) {
    /**
     * @param Model|int|string $id
     */
    function setPermissionsTeamId(Model | int | string $id)
    : void {
        app(PermissionRegistrar::class)->setPermissionsTeamId($id);
    }
}

if (! function_exists('getPermissionsTeamId')) {
    /**
     * @return int|string
     */
    function getPermissionsTeamId()
    : int | string {
        return app(PermissionRegistrar::class)->getPermissionsTeamId();
    }
}
