using System;

namespace FileFox_Backend.Models;

public class User
{
    public Guid Id { get; set; }
    public required string UserName { get; set; } = string.Empty;
    public required string Email { get; set; } = string.Empty;
    public required string PasswordHash { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public ICollection<FileRecord> Files { get; set; } = new List<FileRecord>();
    public string Role { get; set; } = "User";
}
