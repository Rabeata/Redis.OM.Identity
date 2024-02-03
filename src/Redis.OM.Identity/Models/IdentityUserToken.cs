// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Identity;
using Redis.OM.Modeling;
using System;

namespace Redis.OM.Identity.Models;

/// <summary>
/// Represents an authentication token for a user.
/// </summary>
[Document(StorageType = StorageType.Json, IdGenerationStrategyName = "Uuid4IdGenerationStrategy", Prefixes = new[] { nameof(IdentityUserToken) })]
public class IdentityUserToken
{
    /// <summary>
    /// Gets or sets the primary key of the user that the token belongs to.
    /// </summary>
    [Indexed]
    public virtual Guid UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the LoginProvider this token is from.
    /// </summary>
    [Indexed]
    public virtual string LoginProvider { get; set; } = default!;

    /// <summary>
    /// Gets or sets the name of the token.
    /// </summary>
    [Indexed]
    public virtual string Name { get; set; } = default!;

    /// <summary>
    /// Gets or sets the token value.
    /// </summary>
    [ProtectedPersonalData]
    [Indexed]
    public virtual string? Value { get; set; }
}
