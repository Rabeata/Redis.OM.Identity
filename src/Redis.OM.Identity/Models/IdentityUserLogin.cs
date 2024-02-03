// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Redis.OM.Modeling;
using System;

namespace Redis.OM.Identity.Models;

/// <summary>
/// Represents a login and its associated provider for a user.
/// </summary>
[Document(StorageType = StorageType.Json, IdGenerationStrategyName = "Uuid4IdGenerationStrategy", Prefixes = new[] { nameof(IdentityUserLogin) })]

public class IdentityUserLogin
{
    /// <summary>
    /// Gets or sets the login provider for the login (e.g. facebook, google)
    /// </summary>
    [Indexed]
    public virtual string LoginProvider { get; set; } = default!;

    /// <summary>
    /// Gets or sets the unique provider identifier for this login.
    /// </summary>
    [Indexed]
    public virtual string ProviderKey { get; set; } = default!;

    /// <summary>
    /// Gets or sets the friendly name used in a UI for this login.
    /// </summary>
    [Indexed]
    public virtual string? ProviderDisplayName { get; set; }

    /// <summary>
    /// Gets or sets the primary key of the user associated with this login.
    /// </summary>
    [Indexed]
    public virtual Guid UserId { get; set; } = default!;
}
