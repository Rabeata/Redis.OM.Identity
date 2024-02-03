// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Redis.OM.Modeling;
using System;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents a claim that is granted to all users within a role.
/// </summary>
[Document(StorageType = StorageType.Json, IdGenerationStrategyName = "Uuid4IdGenerationStrategy", Prefixes = new[] { nameof(IdentityRoleClaim) })]
public class IdentityRoleClaim
{
    /// <summary>
    /// Gets or sets the identifier for this role claim.
    /// </summary>
    [Indexed]
    [RedisIdField]
    public virtual Guid Id { get; set; } = default!;

    /// <summary>
    /// Gets or sets the of the primary key of the role associated with this claim.
    /// </summary>
    [Indexed]
    public virtual Guid RoleId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the claim type for this claim.
    /// </summary>
    [Indexed]
    public virtual string? ClaimType { get; set; }

    /// <summary>
    /// Gets or sets the claim value for this claim.
    /// </summary>
    [Indexed]
    public virtual string? ClaimValue { get; set; }

    /// <summary>
    /// Constructs a new claim with the type and value.
    /// </summary>
    /// <returns>The <see cref="Claim"/> that was produced.</returns>
    public virtual Claim ToClaim()
    {
        return new Claim(ClaimType!, ClaimValue!);
    }

    /// <summary>
    /// Initializes by copying ClaimType and ClaimValue from the other claim.
    /// </summary>
    /// <param name="other">The claim to initialize from.</param>
    public virtual void InitializeFromClaim(Claim? other)
    {
        ClaimType = other?.Type;
        ClaimValue = other?.Value;
    }
}
