<?php

namespace Oricodes\TenantPermission;

use DateInterval;
use Illuminate\Cache\CacheManager;
use Illuminate\Contracts\Auth\Access\Authorizable;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Cache\Store;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Oricodes\TenantPermission\Contracts\Permission;
use function array_key_exists;

class PermissionRegistrar {
	public string $pivotPermission;
	/** @var DateInterval|int */
	public int | DateInterval $cacheExpirationTime;
	public string $cacheKey;
	protected Repository $cache;
	protected CacheManager $cacheManager;
	protected string $permissionClass;
	/** @var Collection|array|null */
	protected array | null | Collection $permissions;

	private array $alias = [];

	private array $except = [];

	private array $wildcardPermissionsIndex = [];

	/**
	 * PermissionRegistrar constructor.
	 */
	public function __construct(CacheManager $cacheManager) {
		$this->permissionClass = config('tenant-permission.models.permission');

		$this->cacheManager = $cacheManager;
		$this->initializeCache();
	}

	public function initializeCache()
	: void {
		$this->cacheExpirationTime = config('tenant-permission.cache.expiration_time') ?: DateInterval::createFromDateString('24 hours');

		$this->cacheKey = config('tenant-permission.cache.key');

		$this->pivotPermission = config('tenant-permission.column_names.permission_pivot_key') ?: 'permission_id';

		$this->cache = $this->getCacheStoreFromConfig();
	}

	protected function getCacheStoreFromConfig()
	: Repository {
		// the 'default' fallback here is from the tenant-permission.php config file,
		// where 'default' means to use config(cache.default)
		$cacheDriver = config('tenant-permission.cache.store', 'default');

		// when 'default' is specified, no action is required since we already have the default instance
		if ($cacheDriver === 'default') {
			return $this->cacheManager->store();
		}

		// if an undefined cache store is specified, fallback to 'array' which is Laravel closest equiv to 'none'
		if (!array_key_exists($cacheDriver, config('cache.stores'))) {
			$cacheDriver = 'array';
		}

		return $this->cacheManager->store($cacheDriver);
	}

	public static function isUid($value)
	: bool {
		if (!is_string($value) || empty(trim($value))) {
			return false;
		}

		// check if is UUID/GUID
		$uid = preg_match('/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/iD', $value) > 0;
		if ($uid) {
			return true;
		}

		// check if is ULID
		$ulid = strlen($value) == 26 && strspn($value, '0123456789ABCDEFGHJKMNPQRSTVWXYZabcdefghjkmnpqrstvwxyz') == 26 && $value[0] <= '7';
		if ($ulid) {
			return true;
		}

		return false;
	}

	/**
	 * Register the permission check method on the gate.
	 * We resolve the Gate fresh here, for benefit of long-running instances.
	 */
	public function registerPermissions(Gate $gate)
	: bool {
		$gate->before(function (Authorizable $user, string $ability, array &$args = []) {
			if (is_string($args[0] ?? null) && !class_exists($args[0])) {
				$tenant = array_shift($args);
			}
			if (method_exists($user, 'checkPermissionTo')) {
				return $user->checkPermissionTo($ability, $tenant ?? null) ?: null;
			}
		});

		return true;
	}

	public function getWildcardPermissionIndex(Model $record)
	: array {
		if (isset($this->wildcardPermissionsIndex[get_class($record)][$record->getKey()])) {
			return $this->wildcardPermissionsIndex[get_class($record)][$record->getKey()];
		}

		return $this->wildcardPermissionsIndex[get_class($record)][$record->getKey()] = app($record->getWildcardClass(), ['record' => $record])->getIndex();
	}

	/**
	 * Clear already-loaded permissions collection.
	 * This is only intended to be called by the PermissionServiceProvider on boot,
	 * so that long-running instances like Octane or Swoole don't keep old data in memory.
	 */
	public function clearPermissionsCollection()
	: void {
		$this->permissions = null;
		$this->wildcardPermissionsIndex = [];
	}

	/**
	 * Get the permissions based on the passed params.
	 */
	public function getPermissions(array $params = [], bool $onlyOne = false)
	: Collection {
		$this->loadPermissions();

		$method = $onlyOne ? 'first' : 'filter';

		$permissions = $this->permissions->$method(static function ($permission) use ($params) {
			foreach ($params as $attr => $value) {
				if ($permission->getAttribute($attr) != $value) {
					return false;
				}
			}

			return true;
		});

		if ($onlyOne) {
			$permissions = new Collection($permissions ? [$permissions] : []);
		}

		return $permissions;
	}

	/**
	 * Load permissions from cache
	 * And turns permissions array into a \Illuminate\Database\Eloquent\Collection
	 */
	private function loadPermissions()
	: void {
		if ($this->permissions) {
			return;
		}

		$this->permissions = $this->cache->remember(
			$this->cacheKey, $this->cacheExpirationTime, fn() => $this->getSerializedPermissionsForCache()
		);

		// fallback for old cache method must be removed on next mayor version
		if (!isset($this->permissions['alias'])) {
			$this->forgetCachedPermissions();
			$this->loadPermissions();

			return;
		}

		$this->alias = $this->permissions['alias'];

		$this->permissions = $this->getHydratedPermissionCollection();
	}

	private function getSerializedPermissionsForCache()
	: array {
		$this->except = config('tenant-permission.cache.column_names_except', ['created_at', 'updated_at', 'deleted_at'
		]);

		$permissions = $this->permissionClass::select()
			->get()
			->map(function ($permission) {
				if (!$this->alias) {
					$this->aliasModelFields($permission);
				}

				return $this->aliasedArray($permission);
			})->all();

		return ['alias' => array_flip($this->alias)] + compact('permissions');
	}

	/**
	 * Array for cache alias
	 */
	private function aliasModelFields($newKeys = [])
	: void {
		$i = 0;
		$alphas = !count($this->alias) ? range('a', 'h') : range('j', 'p');

		foreach (array_keys($newKeys->getAttributes()) as $value) {
			if (!isset($this->alias[$value])) {
				$this->alias[$value] = $alphas[$i++] ?? $value;
			}
		}

		$this->alias = array_diff_key($this->alias, array_flip($this->except));
	}

	/**
	 * Changes array keys with alias
	 */
	private function aliasedArray($model)
	: array {
		return collect(is_array($model) ? $model : $model->getAttributes())->except($this->except)
			->keyBy(fn($value, $key) => $this->alias[$key] ?? $key)
			->all();
	}

	/**
	 * Flush the cache.
	 */
	public function forgetCachedPermissions()
	: bool {
		$this->permissions = null;
		$this->forgetWildcardPermissionIndex();

		return $this->cache->forget($this->cacheKey);
	}

	public function forgetWildcardPermissionIndex(?Model $record = null)
	: void {
		if ($record) {
			unset($this->wildcardPermissionsIndex[get_class($record)][$record->getKey()]);

			return;
		}

		$this->wildcardPermissionsIndex = [];
	}

	/*
	 * Make the cache smaller using an array with only required fields
	 */

	private function getHydratedPermissionCollection()
	: Collection {
		$permissionInstance = new ($this->getPermissionClass());

		return Collection::make(array_map(
			fn($item) => $permissionInstance->newInstance([], true)
				->setRawAttributes($this->aliasedArray(array_diff_key($item, ['r' => 0])), true),
			$this->permissions['permissions']
		));
	}

	public function getPermissionClass()
	: string {
		return $this->permissionClass;
	}

	public function setPermissionClass($permissionClass)
	: static {
		$this->permissionClass = $permissionClass;
		config()->set('permission.models.permission', $permissionClass);
		app()->bind(Permission::class, $permissionClass);

		return $this;
	}

	public function getCacheRepository()
	: Repository {
		return $this->cache;
	}

	public function getCacheStore()
	: Store {
		return $this->cache->getStore();
	}
}
