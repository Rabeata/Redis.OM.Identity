// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Redis.OM.Modeling;
using System;

namespace Redis.OM.Identity.Models;

/// <summary>
/// Represents a role in the identity system
/// </summary>
[Document(StorageType = StorageType.Json, IdGenerationStrategyName = "Uuid4IdGenerationStrategy", Prefixes = new[] { nameof(IdentityRole) })]
public class IdentityRole
{
    /// <summary>
    /// Initializes a new instance of <see cref="IdentityRole{Guid}"/>.
    /// </summary>
    public IdentityRole() { }

    /// <summary>
    /// Initializes a new instance of <see cref="IdentityRole{Guid}"/>.
    /// </summary>
    /// <param name="roleName">The role name.</param>
    public IdentityRole(string roleName) : this()
    {
        Name = roleName;
    }

    /// <summary>
    /// Gets or sets the primary key for this role.
    /// </summary>
    [Indexed]
    [RedisIdField]
    public virtual Guid Id { get; set; } = default!;

    /// <summary>
    /// Gets or sets the name for this role.
    /// </summary>
    [Indexed]
    public virtual string? Name { get; set; }

    /// <summary>
    /// Gets or sets the normalized name for this role.
    /// </summary>
    [Indexed]
    public virtual string? NormalizedName { get; set; }

    /// <summary>
    /// A random value that should change whenever a role is persisted to the store
    /// </summary>
    [Indexed]
    public virtual string? ConcurrencyStamp { get; set; }

    /// <summary>
    /// Returns the name of the role.
    /// </summary>
    /// <returns>The name of the role.</returns>
    public override string ToString()
    {
        return Name ?? string.Empty;
    }
}
