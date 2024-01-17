<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
	/**
	 * Run the migrations.
	 */
	public function up()
	: void {
		$teams = config('tenant-permission.teams');
		$tableNames = config('tenant-permission.table_names');
		$columnNames = config('tenant-permission.column_names');
		$pivotPermission = $columnNames['permission_pivot_key'] ?? 'permission_id';

		if (empty($tableNames)) {
			throw new Exception('Error: config/tenant-permission.php not loaded. Run [php artisan config:clear] and try again.');
		}
		if ($teams && empty($columnNames['team_foreign_key'] ?? null)) {
			throw new Exception('Error: team_foreign_key on config/tenant-permission.php not loaded. Run [php artisan config:clear] and try again.');
		}

		Schema::create($tableNames['permissions'], function (Blueprint $table) {
			$table->bigIncrements('id');         // permission id
			$table->string('name');              // For MySQL 8.0 use string('name', 125);
			$table->string('tenant_name');       // For MySQL 8.0 use string('name', 125);
			$table->timestamps();

			$table->unique(['name']);
		});

		Schema::create($tableNames['model_has_permissions'], function (Blueprint $table) use ($tableNames, $columnNames, $pivotPermission) {
			$table->unsignedBigInteger($pivotPermission);

			$table->string('model_type');
			$table->string('tenant_name');       // For MySQL 8.0 use string('name', 125);
			$table->unsignedBigInteger($columnNames['model_morph_key']);
			$table->index([$columnNames['model_morph_key'], 'model_type', 'tenant_name'
			], 'model_has_permissions_model_id_model_type_tenant_name_index');

			$table->foreign($pivotPermission)
				->references('id') // permission id
				->on($tableNames['permissions'])
				->onDelete('cascade');

			$table->primary([$pivotPermission, $columnNames['model_morph_key'], 'model_type', 'tenant_name'],
				'model_has_permissions_permission_model_type_tenant_name_primary');
		});

		app('cache')
			->store(config('tenant-permission.cache.store') != 'default' ? config('tenant-permission.cache.store') : null)
			->forget(config('tenant-permission.cache.key'));
	}

	/**
	 * Reverse the migrations.
	 */
	public function down()
	: void {
		$tableNames = config('tenant-permission.table_names');

		if (empty($tableNames)) {
			throw new Exception('Error: config/tenant-permission.php not found and defaults could not be merged. Please publish the package configuration before proceeding, or drop the tables manually.');
		}

		Schema::drop($tableNames['model_has_permissions']);
		Schema::drop($tableNames['permissions']);
	}
};
