<?php

namespace Oricodes\TenantPermission;

use Illuminate\Contracts\Auth\Access\Authorizable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use ReflectionClass;
use ReflectionException;
use function method_exists;

class Guard
{
    /**
     * Lookup a guard name relevant for the $class model and the current user.
     *
     * @param string|Model $class model class object or name
     * @return string guard name
     */
    public static function getDefaultName(Model | string $class): string
    {
        $default = config('auth.defaults.guard');

        $possible_guards = static::getNames($class);

        // return current-detected auth.defaults.guard if it matches one of those that have been checked
        if ($possible_guards->contains($default)) {
            return $default;
        }

        return $possible_guards->first() ?: $default;
    }

	/**
	 * Return a collection of guard names suitable for the $model,
	 * as indicated by the presence of a $tenant_name property or a guardName() method on the model.
	 *
	 * @param string|Model $model model class object or name
	 * @throws ReflectionException
	 */
    public static function getNames(Model | string $model): Collection
    {
        $class = is_object($model) ? get_class($model) : $model;

        if (is_object($model)) {
            if (method_exists($model, 'guardName')) {
                $tenantName = $model->guardName();
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
    }

    /**
     * Get list of relevant guards for the $class model based on config(auth) settings.
     *
     * Lookup flow:
     * - get names of models for guards defined in auth.guards where a provider is set
     * - filter for provider models matching the model $class being checked (important for Lumen)
     * - keys() gives just the names of the matched guards
     * - return collection of guard names
     */
    protected static function getConfigAuthGuards(string $class): Collection
    {
        return collect(config('auth.guards'))
            ->map(fn ($tenant) => isset($tenant['provider']) ? config("auth.providers.{$tenant['provider']}.model") : null)
            ->filter(fn ($model) => $class === $model)
            ->keys();
    }

    /**
     * Lookup a passport guard
     */
    public static function getPassportClient($tenant): ?Authorizable
    {
        $tenants = collect(config('auth.guards'))->where('driver', 'passport');

        if (! $tenants->count()) {
            return null;
        }

        $authGuard = Auth::guard($tenants->keys()[0]);

        if (! method_exists($authGuard, 'client')) {
            return null;
        }

        $client = $authGuard->client();

        if (! $tenant || ! $client) {
            return $client;
        }

        if (self::getNames($client)->contains($tenant)) {
            return $client;
        }

        return null;
    }
}
