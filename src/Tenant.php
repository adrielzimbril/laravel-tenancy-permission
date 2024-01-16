<?php

namespace Oricodes\TenantPermission;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use ReflectionClass;
use ReflectionException;
use function method_exists;

class Tenant
{
	/**
	 * Lookup a tenant name relevant for the $class model and the current user.
	 *
	 * @return string tenant name
	 */
    public static function getDefaultName(): string
    {
        $default = '';

        return tenant() ? tenant()->id : $default;
    }

	/**
	 * Return a collection of tenant names suitable for the $model,
	 * as indicated by the presence of a $tenant_name property or a tenantName() method on the model.
	 *
	 * @param string|Model $model model class object or name
	 * @throws ReflectionException
	 */
    public static function getNames(Model | string $model): Collection
    {
		/*
        $class = is_object($model) ? get_class($model) : $model;

        if (is_object($model)) {
            if (method_exists($model, 'tenantName')) {
                $tenantName = $model->tenantName();
            } else {
                $tenantName = $model->getAttributeValue('tenant_name');
            }
        }

        if (! isset($tenantName)) {
            $tenantName = (new ReflectionClass($class))->getDefaultProperties()['tenant_name'] ?? null;
        }

        if ($tenantName) {
            return collect($tenantName);
        }

	    return self::getConfigAuthGuards($class);
		*/

	    $tenantName = tenant()->tenants->pluck('id');

	    return collect($tenantName);
    }

    /**
     * Get list of relevant tenants for the $class model based on config(auth) settings.
     *
     * Lookup flow:
     * - get names of models for tenants defined in auth.tenants where a provider is set
     * - filter for provider models matching the model $class being checked (important for Lumen)
     * - keys() gives just the names of the matched tenants
     * - return collection of tenant names
     */
    protected static function getConfigAuthGuards(string $class): Collection
    {
        return collect(config('auth.tenants'))
            ->map(fn ($tenant) => isset($tenant['provider']) ? config("auth.providers.{$tenant['provider']}.model") : null)
            ->filter(fn ($model) => $class === $model)
            ->keys();
    }
}
