using System;

// This describes a user account we store in memory.
namespace FileFox_Backend.Models;

public class User
{
    public Guid Id { get; set; }
    public required string UserName { get; set; } = string.Empty;
    public required byte[] PasswordHash { get; set; } = Array.Empty<byte>();
    public required byte[] PasswordSalt { get; set; } = Array.Empty<byte>();
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public ICollection<FileRecord> Files { get; set; } = new List<FileRecord>();
}