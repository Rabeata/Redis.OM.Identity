using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Redis.OM;
using Redis.OM.Identity.Models;
using StackExchange.Redis;

namespace Redis.OM.Identity;

/// <summary>
/// Contains extension methods to <see cref="IdentityBuilder"/> for adding redis stores.
/// </summary>
public static class IdentityRedisOMBuilderExtensions
{
    /// <summary>
    /// Adds an implementation of identity information stores.
    /// </summary>
    /// <typeparam name="TContext">The Redis database context to use.</typeparam>
    /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
    /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
    public static IdentityBuilder AddRedisOMStores(this IdentityBuilder builder, Func<IServiceProvider, RedisConnectionProvider> getDatabase)
    {

        AddStores(builder.Services, builder.UserType, builder.RoleType, typeof(IdentityDbContext));
        return builder;
    }


    /// <summary>
    /// Adds an Redis implementation of identity stores.
    /// </summary>
    /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
    /// <param name="configure">Action to configure <see cref="ConfigurationOptions"/></param>
    /// <param name="database">(Optional) The redis database to use</param>
    /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
    public static IdentityBuilder AddRedisOMStores(this IdentityBuilder builder, Action<ConfigurationOptions> configure)
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

    private static void AddStores(IServiceCollection services, Type userType, Type? roleType, Type contextType)
    {
        var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser));
        if (identityUserType == null)
        {
            throw new InvalidOperationException("AddRedisOMStores can only be called with a user that derives from IdentityUser.");
        }

        if (roleType != null)
        {
            var identityRoleType = FindGenericBaseType(roleType, typeof(IdentityRole));
            if (identityRoleType == null)
            {
                throw new InvalidOperationException("AddRedisOMStores can only be called with a role that derives from IdentityRole.");
            }

            Type userStoreType;
            Type roleStoreType;
            var identityContext = FindGenericBaseType(contextType, typeof(IdentityDbContext<,,,,,,>));
            if (identityContext == null)
            {
                // If its a custom RedisContext, we can only add the default POCOs
                userStoreType = typeof(UserStore<,,>).MakeGenericType(userType, roleType, contextType);
                roleStoreType = typeof(RoleStore<,>).MakeGenericType(roleType, contextType);
            }
            else
            {
                userStoreType = typeof(UserStore<,,,,,,,>).MakeGenericType(userType, roleType, contextType,
                    identityContext.GenericTypeArguments[2],
                    identityContext.GenericTypeArguments[3],
                    identityContext.GenericTypeArguments[4],
                    identityContext.GenericTypeArguments[5],
                    identityContext.GenericTypeArguments[7],
                    identityContext.GenericTypeArguments[6]);
                roleStoreType = typeof(RoleStore<,,,>).MakeGenericType(roleType, contextType,
                    identityContext.GenericTypeArguments[2],
                    identityContext.GenericTypeArguments[4],
                    identityContext.GenericTypeArguments[6]);
            }
            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
            services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);
        }
        else
        {   // No Roles
            Type userStoreType;
            var identityContext = FindGenericBaseType(contextType, typeof(IdentityDbContext<,,,,,,>));
            if (identityContext == null)
            {
                // If its a custom RedisContext, we can only add the default POCOs
                userStoreType = typeof(UserOnlyStore<,>).MakeGenericType(userType, contextType);
            }
            else
            {
                userStoreType = typeof(UserOnlyStore<,,,,>).MakeGenericType(userType, contextType,
                    identityContext.GenericTypeArguments[1],
                    identityContext.GenericTypeArguments[2],
                    identityContext.GenericTypeArguments[3],
                    identityContext.GenericTypeArguments[4]);
            }
            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
        }

    }

    private static Type? FindGenericBaseType(Type currentType, Type genericBaseType)
    {
        Type? type = currentType;
        while (type != null)
        {
            var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
            if (genericType != null && genericType == genericBaseType)
            {
                return type;
            }
            type = type.BaseType;
        }
        return null;
    }
}
