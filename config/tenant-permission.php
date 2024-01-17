<?php

return [

	'models' => [

		/*
		 * When using the "HasPermissions" trait from this package, we need to know which
		 * Eloquent model should be used to retrieve your permissions. Of course, it
		 * is often just the "Permission" model but you may use whatever you like.
		 *
		 * The model you want to use as a Permission model needs to implement the
		 * `Oricodes\TenantPermission\Contracts\Permission` contract.
		 */

		'permission' => Oricodes\TenantPermission\Models\Permission::class,
	],

	'table_names' => [
		/*
		 * When using the "HasPermissions" trait from this package, we need to know which
		 * table should be used to retrieve your permissions. We have chosen a basic
		 * default value but you may easily change it to any table you like.
		 */

		'permissions' => 'tenant_permissions',

		/*
		 * When using the "HasPermissions" trait from this package, we need to know which
		 * table should be used to retrieve your models permissions. We have chosen a
		 * basic default value but you may easily change it to any table you like.
		 */

		'model_has_permissions' => 'tenant_model_has_permissions',
	],

	'column_names' => [
		'permission_pivot_key' => 'tenant_permission_id', //default 'permission_id',

		/*
		 * Change this if you want to name the related model primary key other than
		 * `model_id`.
		 *
		 * For example, this would be nice if your primary keys are all UUIDs. In
		 * that case, name this `model_uuid`.
		 */

		'model_morph_key' => 'tenant_model_id',
	],

	/*
	 * When set to true, the method for checking permissions will be registered on the gate.
	 * Set this to false if you want to implement custom logic for checking permissions.
	 */

	'register_permission_check_method' => true,

	/*
	 * When set to true, Laravel\Octane\Events\OperationTerminated event listener will be registered
	 * this will refresh permissions on every TickTerminated, TaskTerminated and RequestTerminated
	 * NOTE: This should not be needed in most cases, but an Octane/Vapor combination benefited from it.
	 */
	'register_octane_reset_listener'   => false,

	/*
	 * Passport Client Credentials Grant
	 * When set to true, the package will use Passports Client to check permissions
	 */

	'use_passport_client_credentials' => false,

	/*
	 * When set to true, the required permission names are added to exception messages.
	 * This could be considered an information leak in some contexts, so the default
	 * setting is false here for optimum safety.
	 */

	'display_permission_in_exception' => false,

	/*
	 * When set to true, the required role names are added to exception messages.
	 * This could be considered an information leak in some contexts, so the default
	 * setting is false here for optimum safety.
	 */

	'display_role_in_exception' => false,

	/*
	 * By default, wildcard permission lookups are disabled.
	 * See documentation to understand the supported syntax.
	 */

	'enable_wildcard_permission' => true,

	/*
	 * The class to use for interpreting wildcard permissions.
	 * If you need to modify delimiters, override the class and specify its name here.
	 */
	// 'permission.wildcard_permission' => Oricodes\TenantPermission\WildcardPermission::class,

	/* Cache-specific settings */

	'cache' => [

		/*
		 * By default, all permissions are cached for 24 hours to speed up performance.
		 * When permissions or roles are updated, the cache is flushed automatically.
		 */

		'expiration_time' => DateInterval::createFromDateString('24 hours'),

		/*
		 * The cache key used to store all permissions.
		 */

		'key' => 'tenant.permission.cache',

		/*
		 * You may optionally indicate a specific cache driver to use for permission and
		 * role caching using any of the `store` drivers listed in the cache.php config
		 * file. Using 'default' here means to use the `default` set in cache.php.
		 */

		'store' => 'default',
	],
];
