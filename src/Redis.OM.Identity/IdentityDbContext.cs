using Redis.OM;
using Redis.OM.Identity.Models;
using Redis.OM.Searching;

namespace Redis.OM.Identity;

///// <summary>
///// Base class for the Entity Framework database context used for identity.
///// </summary>
//public class IdentityDbContext : IdentityDbContext<IdentityUser, IdentityRole>
//{
//    /// <summary>
//    /// Initializes a new instance of <see cref="IdentityDbContext"/>.
//    /// </summary>
//    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
//    public IdentityDbContext(RedisConnectionProvider db) : base(db) { }

//}

/// <summary>
/// Base class for the Entity Framework database context used for identity.
/// </summary>
/// <typeparam name="TUser">The type of the user objects.</typeparam>
public class IdentityDbContext<TUser> : IdentityDbContext<TUser, IdentityRole> where TUser : IdentityUser
{
    /// <summary>
    /// Initializes a new instance of <see cref="IdentityDbContext"/>.
    /// </summary>
    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
    public IdentityDbContext(RedisConnectionProvider db) : base(db) { }


}



/// <summary>
/// Base class for the Entity Framework database context used for identity.
/// </summary>
/// <typeparam name="TUser">The type of user objects.</typeparam>
/// <typeparam name="TRole">The type of role objects.</typeparam>
/// <typeparam name="TKey">The type of the primary key for users and roles.</typeparam>
public class IdentityDbContext<TUser, TRole> : IdentityDbContext<TUser, TRole, IdentityUserClaim, IdentityUserRole, IdentityUserLogin, IdentityRoleClaim, IdentityUserToken>
    where TUser : IdentityUser
    where TRole : IdentityRole
{
    /// <summary>
    /// Initializes a new instance of the db context.
    /// </summary>
    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
    public IdentityDbContext(RedisConnectionProvider db) : base(db) { }

}

/// <summary>
/// Base class for the Entity Framework database context used for identity.
/// </summary>
/// <typeparam name="TUser">The type of user objects.</typeparam>
/// <typeparam name="TRole">The type of role objects.</typeparam>
/// <typeparam name="TUserClaim">The type of the user claim object.</typeparam>
/// <typeparam name="TUserRole">The type of the user role object.</typeparam>
/// <typeparam name="TUserLogin">The type of the user login object.</typeparam>
/// <typeparam name="TRoleClaim">The type of the role claim object.</typeparam>
/// <typeparam name="TUserToken">The type of the user token object.</typeparam>
public abstract class IdentityDbContext<TUser, TRole, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>
    where TUser : IdentityUser
    where TRole : IdentityRole
    where TUserClaim : IdentityUserClaim
    where TUserRole : IdentityUserRole
    where TUserLogin : IdentityUserLogin
    where TRoleClaim : IdentityRoleClaim
    where TUserToken : IdentityUserToken
{
    /// <summary>
    /// Initializes a new instance of the class.
    /// </summary>
    /// <param name="options">The options to be used by a <see cref="DbContext"/>.</param>
    public IdentityDbContext(RedisConnectionProvider db)
    {

        UserRoles = (RedisCollection<TUserRole>)db.RedisCollection<TUserRole>();
        Roles = (RedisCollection<TRole>)db.RedisCollection<TRole>();
        UserClaims = (RedisCollection<TUserClaim>)db.RedisCollection<TUserClaim>();
        Users = (RedisCollection<TUser>)db.RedisCollection<TUser>();
        UserLogins = (RedisCollection<TUserLogin>)db.RedisCollection<TUserLogin>();
        RoleClaims = (RedisCollection<TRoleClaim>)db.RedisCollection<TRoleClaim>();
        UserTokens = (RedisCollection<TUserToken>)db.RedisCollection<TUserToken>();

    }

    /// <summary>
    /// Gets or sets the <see cref="IRedisCollection{TEntity}"/> of User roles.
    /// </summary>
    public virtual IRedisCollection<TUserRole> UserRoles { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IRedisCollection{TEntity}"/> of roles.
    /// </summary>
    public virtual IRedisCollection<TRole> Roles { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IRedisCollection{TEntity}"/> of role claims.
    /// </summary>
    public virtual IRedisCollection<TRoleClaim> RoleClaims { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IRedisCollection{TEntity}"/> of Users.
    /// </summary>
    public virtual IRedisCollection<TUser> Users { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IRedisCollection{TEntity}"/> of User claims.
    /// </summary>
    public virtual IRedisCollection<TUserClaim> UserClaims { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IRedisCollection{TEntity}"/> of User logins.
    /// </summary>
    public virtual IRedisCollection<TUserLogin> UserLogins { get; set; } = default!;

    /// <summary>
    /// Gets or sets the <see cref="IRedisCollection{TEntity}"/> of User tokens.
    /// </summary>
    public virtual IRedisCollection<TUserToken> UserTokens { get; set; } = default!;


}
