<?php

namespace Oricodes\TenantPermission\Commands;

use Illuminate\Console\Command;
use Oricodes\TenantPermission\Contracts\Permission as PermissionContract;

class CreatePermission extends Command
{
    protected $signature = 'permission:create-permission 
                {name : The name of the permission}';

    protected $description = 'Create a permission';

    public function handle()
    : void {
        $permissionClass = app(PermissionContract::class);

        $permission = $permissionClass::findOrCreate($this->argument('name'));

        $this->info("Permission `{$permission->name}` ".($permission->wasRecentlyCreated ? 'created' : 'already exists'));
    }
}
