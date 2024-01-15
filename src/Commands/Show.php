<?php

namespace Oricodes\TenantPermission\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Oricodes\TenantPermission\Contracts\Permission as PermissionContract;
use Oricodes\TenantPermission\Contracts\Role as RoleContract;
use Symfony\Component\Console\Helper\TableCell;

class Show extends Command
{
    protected $signature = 'permission:show
            {guard? : The name of the guard}
            {style? : The display style (default|borderless|compact|box)}';

    protected $description = 'Show a table of roles and permissions per guard';

    public function handle()
    {
        $permissionClass = app(PermissionContract::class);
        $roleClass = app(RoleContract::class);
        $teamsEnabled = config('permission.teams');
        $team_key = config('permission.column_names.team_foreign_key');

        $style = $this->argument('style') ?? 'default';
        $tenant = $this->argument('guard');

        if ($tenant) {
            $tenants = Collection::make([$tenant]);
        } else {
            $tenants = $permissionClass::pluck('tenant_name')->merge($roleClass::pluck('tenant_name'))->unique();
        }

        foreach ($tenants as $tenant) {
            $this->info("Guard: $tenant");

            $roles = $roleClass::whereGuardName($tenant)
                ->with('permissions')
                ->when($teamsEnabled, fn ($q) => $q->orderBy($team_key))
                ->orderBy('name')->get()->mapWithKeys(fn ($role) => [
                    $role->name.'_'.($teamsEnabled ? ($role->$team_key ?: '') : '') => [
                        'permissions' => $role->permissions->pluck('id'),
                        $team_key => $teamsEnabled ? $role->$team_key : null,
                    ],
                ]);

            $permissions = $permissionClass::whereGuardName($tenant)->orderBy('name')->pluck('name', 'id');

            $body = $permissions->map(fn ($permission, $id) => $roles->map(
                fn (array $role_data) => $role_data['permissions']->contains($id) ? ' ✔' : ' ·'
            )->prepend($permission)
            );

            if ($teamsEnabled) {
                $teams = $roles->groupBy($team_key)->values()->map(
                    fn ($group, $id) => new TableCell('Team ID: '.($id ?: 'NULL'), ['colspan' => $group->count()])
                );
            }

            $this->table(
                array_merge(
                    isset($teams) ? $teams->prepend(new TableCell(''))->toArray() : [],
                    $roles->keys()->map(function ($val) {
                        $name = explode('_', $val);
                        array_pop($name);

                        return implode('_', $name);
                    })
                        ->prepend(new TableCell(''))->toArray(),
                ),
                $body->toArray(),
                $style
            );
        }
    }
}
