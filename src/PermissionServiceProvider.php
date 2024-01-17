<?php

namespace Oricodes\TenantPermission;

use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Routing\Route;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\ServiceProvider;
use Illuminate\View\Compilers\BladeCompiler;
use Laravel\Octane\Events\OperationTerminated;
use Oricodes\TenantPermission\Contracts\Permission as PermissionContract;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

class PermissionServiceProvider extends ServiceProvider {
	public static function bladeMethodWrapper($method, $tenant = null)
	: bool {
		$guard = 'tenant_user';
		return auth($guard)->check() && auth($guard)->user()->{$method};
	}

	/**
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 */
	/**
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 */
	public function boot()
	: void {
		$this->offerPublishing();

		$this->registerMacroHelpers();

		$this->registerCommands();

		$this->registerModelBindings();

		$this->registerOctaneListener();

		$this->callAfterResolving(Gate::class, function (Gate $gate, Application $app) {
			if ($this->app['config']->get('permission.register_permission_check_method')) {
				/** @var PermissionRegistrar $permissionLoader */
				$permissionLoader = $app->get(PermissionRegistrar::class);
				$permissionLoader->clearPermissionsCollection();
				$permissionLoader->registerPermissions($gate);
			}
		});

		$this->app->singleton(PermissionRegistrar::class);
	}

	protected function offerPublishing()
	: void {
		if (!$this->app->runningInConsole()) {
			return;
		}

		if (!function_exists('config_path')) {
			// function not available and 'publish' not relevant in Lumen
			return;
		}

		$this->publishes([
			__DIR__ . '/../config/tenant-permission.php' => config_path('tenant-permission.php'),
		], 'permission-config');

		$this->publishes([
			__DIR__ . '/../database/migrations/create_permission_tables.php.stub' => $this->getMigrationFileName('create_permission_tables.php'),
		], 'permission-migrations');
	}

	/**
	 * Returns existing migration file if found, else uses the current timestamp.
	 * @throws BindingResolutionException
	 */
	protected function getMigrationFileName(string $migrationFileName)
	: string {
		$timestamp = date('Y_m_d_His');

		$filesystem = $this->app->make(Filesystem::class);

		return Collection::make([$this->app->databasePath() . DIRECTORY_SEPARATOR . 'migrations' . DIRECTORY_SEPARATOR])
			->flatMap(fn($path) => $filesystem->glob($path . '*_' . $migrationFileName))
			->push($this->app->databasePath() . "/migrations/{$timestamp}_{$migrationFileName}")
			->first();
	}

	protected function registerMacroHelpers()
	: void {
		if (!method_exists(Route::class, 'macro')) { // Lumen
			return;
		}

		Route::macro('permission', function ($permissions = []) {
			/** @var Route $this */
			return $this->middleware('permission:' . implode('|', Arr::wrap($permissions)));
		});
	}

	protected function registerCommands()
	: void {
		$this->commands([
			Commands\CacheReset::class,
		]);

		if (!$this->app->runningInConsole()) {
			return;
		}

		$this->commands([
			Commands\CreatePermission::class,
			Commands\Show::class,
		]);
	}

	protected function registerModelBindings()
	: void {
		$this->app->bind(PermissionContract::class, fn($app) => $app->make($app->config['permission.models.permission']));
	}

	protected function registerOctaneListener()
	: void {
		if ($this->app->runningInConsole() || !$this->app['config']->get('octane.listeners')) {
			return;
		}

		$dispatcher = $this->app[Dispatcher::class];
		// @phpstan-ignore-next-line
		$dispatcher->listen(function (OperationTerminated $event) {
			// @phpstan-ignore-next-line
			$event->sandbox->make(PermissionRegistrar::class)->setPermissionsTeamId(null);
		});

		if (!$this->app['config']->get('permission.register_octane_reset_listener')) {
			return;
		}
		// @phpstan-ignore-next-line
		$dispatcher->listen(function (OperationTerminated $event) {
			// @phpstan-ignore-next-line
			$event->sandbox->make(PermissionRegistrar::class)->clearPermissionsCollection();
		});
	}

	public function register()
	: void {
		$this->mergeConfigFrom(
			__DIR__ . '/../config/tenant-permission.php',
			'permission'
		);

		$this->callAfterResolving('blade.compiler', fn(BladeCompiler $bladeCompiler) => $this->registerBladeExtensions($bladeCompiler));
	}

	protected function registerBladeExtensions($bladeCompiler)
	: void {
		$bladeMethodWrapper = '\\Oricodes\\TenantPermission\\PermissionServiceProvider::bladeMethodWrapper';

		$bladeCompiler->directive('tenanthaspermission', fn($args) => "<?php if({$bladeMethodWrapper}('checkPermissionTo', {$args})): ?>");
		$bladeCompiler->directive('elsehaspermission', fn($args) => "<?php elseif({$bladeMethodWrapper}('checkPermissionTo', {$args})): ?>");
		$bladeCompiler->directive('endtenanthaspermission', fn() => '<?php endif; ?>');
	}
}
