<?php

namespace Oricodes\TenantPermission\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Oricodes\TenantPermission\Contracts\Permission as PermissionContract;
use Oricodes\TenantPermission\Traits\HasPermissions;
use Symfony\Component\Console\Helper\TableCell;

class Show extends Command {
	use HasPermissions;

	protected $signature = 'permission:show
            {tenant? : The name of the tenant}
            {style? : The display style (default|borderless|compact|box)}';

	protected $description = 'Show a table of roles and permissions per tenant';

	public function handle()
	: void {
		$permissionClass = app(PermissionContract::class);

		$style = $this->argument('style') ?? 'default';
		$tenant = $this->argument('tenant');

		if ($tenant) {
			$tenants = Collection::make([$tenant]);
		} else {
			$tenants = $permissionClass::pluck('pivot.tenant_name')->unique();
		}

		foreach ($tenants as $tenant) {
			$this->info("Tenant: $tenant");

			$permissions = $permissionClass::whereGuardName($tenant)->orderBy('name')->pluck('name', 'id');

			$body = $permissions->map(
				function ($permission, $id) use ($tenant) {
					$emoji = $this->hasWildcardPermission($tenant, $id) ? ' ✔' : ' ·';
					return [$permission . $emoji];
				}
			);

			$this->table(
				$permissions->keys()->map(function ($val) {
					return $val;
				})->prepend(new TableCell(''))->toArray(),
				$body->toArray(),
				$style
			);
		}
	}
}
