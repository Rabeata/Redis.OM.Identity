using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Redis.OM.Identity.Models;
using StackExchange.Redis;

namespace Redis.OM.Identity;

/// <summary>
/// Contains extension methods to <see cref="IdentityBuilder"/> for adding redis stores.
/// </summary>
public static class IdentityRedisOMBuilderExtensions
{
    /// <summary>
    /// Adds an Redis implementation of identity stores.
    /// </summary>
    /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
    /// <param name="getDatabase"><see cref="RedisConnectionProvider"/> factory function returning the redis database to use</param>
    /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
    private static IdentityBuilder AddRedisOMStores(this IdentityBuilder builder, Func<IServiceProvider, RedisConnectionProvider> getDatabase)
    {
        AddStores(builder.Services, builder.UserType, builder.RoleType, getDatabase);

        return builder;
    }

    /// <summary>
    /// Adds an Redis implementation of identity stores.
    /// </summary>
    /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
    /// <param name="configure">Action to configure <see cref="ConfigurationOptions"/></param>
    /// <param name="database">(Optional) The redis database to use</param>
    /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
    public static IdentityBuilder AddRedisOMStores(this IdentityBuilder builder, Action<ConfigurationOptions> configure, int? database = null)
    {
        var services = builder.Services;

        services.Configure(configure)
            .AddSingleton<IConnectionMultiplexer>(provider =>
            {
                var options = provider.GetRequiredService<IOptions<ConfigurationOptions>>().Value;
                var redisProvider = new RedisConnectionProvider(options);
                return ConnectionMultiplexer.Connect(options);
            });

        return builder.AddRedisOMStores(provider =>
        {
            var dnProvider = provider.GetRequiredService<RedisConnectionProvider>();
            return dnProvider;


        });
    }

    /// <summary>
    /// Adds an Redis implementation of identity stores.
    /// </summary>
    /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
    /// <param name="configuration">The redis configuration string</param>
    /// <param name="database">(Optional) The redis database to use</param>
    /// <param name="log">(Optional) a <see cref="TextWriter"/> to write log</param>
    /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
    public static IdentityBuilder AddRedisStores(this IdentityBuilder builder, string configuration, int? database = null)
    {
        var services = builder.Services;

        services.AddSingleton<IConnectionMultiplexer>(provider =>
        {

            var redisProvider = new RedisConnectionProvider(configuration);
            return ConnectionMultiplexer.Connect(configuration);
        });

        return builder
            .AddRedisOMStores(provider =>
            {
                var dnProvider = provider.GetRequiredService<RedisConnectionProvider>();
                return dnProvider;
            });
    }


    private static void AddStores(IServiceCollection services, Type userType, Type roleType, Func<IServiceProvider, RedisConnectionProvider> getDatabase)
    {
        var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser));
        if (identityUserType == null)
        {
            throw new InvalidOperationException("AddEntityFrameworkStores can only be called with a user that derives from IdentityUser<TKey>.");
        }

        var userOnlyStoreType = typeof(UserOnlyStore<>).MakeGenericType(userType);

        if (roleType != null)
        {
            var identityRoleType = FindGenericBaseType(roleType, typeof(IdentityRole));
            if (identityRoleType == null)
            {
                throw new InvalidOperationException("AddEntityFrameworkStores can only be called with a role that derives from IdentityRole<TKey>.");
            }

            var userStoreType = typeof(UserStore<,>).MakeGenericType(userType, roleType);
            var roleStoreType = typeof(RoleStore<>).MakeGenericType(roleType);

            services.TryAddScoped(typeof(UserOnlyStore<>).MakeGenericType(userType), provider => CreateStoreInstance(userOnlyStoreType, getDatabase(provider), provider.GetService<IdentityErrorDescriber>()));
            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), provider => userStoreType.GetConstructor(new Type[] { typeof(RedisConnectionProvider),  typeof(IdentityErrorDescriber) })
                .Invoke(new object[] { getDatabase(provider), provider.GetService<IdentityErrorDescriber>() }));
            services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), provider => CreateStoreInstance(roleStoreType, getDatabase(provider), provider.GetService<IdentityErrorDescriber>()));
        }
        else
        {   // No Roles
            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), provider => CreateStoreInstance(userOnlyStoreType, getDatabase(provider), provider.GetService<IdentityErrorDescriber>()));
        }
    }

    private static object CreateStoreInstance(Type storeType, RedisConnectionProvider db, IdentityErrorDescriber errorDescriber)
    {
        var constructor = storeType.GetConstructor(new Type[] { typeof(RedisConnectionProvider), typeof(IdentityErrorDescriber) });
        return constructor.Invoke(new object[] { db, errorDescriber });
    }


    private static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        Type? type = currentType;
        while (type != null)
        {

            if (type == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }
        return null;
    }
}
