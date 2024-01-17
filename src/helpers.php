<?php

if (!function_exists('getModelForUser')) {
	/**
	 * @return string|null
	 */
	function getModelForUser()
	: ?string {
		return App\Models\TenantUser::class;
	}
}

if (!function_exists('getModelForTenant')) {
	/**
	 * @return string|null
	 */
	function getModelForTenant()
	: ?string {
		return App\Models\Tenant::class;
	}
}