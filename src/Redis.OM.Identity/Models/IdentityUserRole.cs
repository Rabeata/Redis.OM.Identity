// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Redis.OM.Modeling;
using System;

namespace Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents the link between a user and a role.
/// </summary>
[Document(StorageType = StorageType.Json, IdGenerationStrategyName = "Uuid4IdGenerationStrategy", Prefixes = new[] { nameof(IdentityUserRole) })]
public class IdentityUserRole
{
    /// <summary>
    /// Gets or sets the primary key of the user that is linked to a role.
    /// </summary>
    [Indexed]
    public virtual Guid UserId { get; set; } = default!;

    /// <summary>
    /// Gets or sets the primary key of the role that is linked to the user.
    /// </summary>
    [Indexed]
    public virtual Guid RoleId { get; set; } = default!;
}
