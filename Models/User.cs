using System;

// This describes a user account we store in memory.
namespace FileFox_Backend.Models;

public class User
{
    public Guid Id { get; init; }
    public required string UserName { get; init; }
    public required byte[] PasswordHash { get; init; }
    public required byte[] PasswordSalt { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}