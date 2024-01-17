<?php

if (!function_exists('getModelForTenant')) {
	/**
	 * @return string|null
	 */
	function getModelForTenant()
	: ?string {
		return App\Models\TenantUser::class;
	}
}