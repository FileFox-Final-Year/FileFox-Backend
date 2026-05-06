using System;

namespace FileFox_Backend.Core.Models;

public class User
{
    public Guid Id { get; set; }
    public required string UserName { get; set; } = string.Empty;
    public required string Email { get; set; } = string.Empty;
    public required string PasswordHash { get; set; } = string.Empty;
    public bool MfaEnabled { get; set; }
    public string? MfaSecret { get; set; }
    public DateTimeOffset? MfaEnabledAt { get; set; }
    public string? MfaRecoveryCodes { get; set; }
    public string? PasswordResetToken { get; set; }
    public DateTimeOffset? PasswordResetTokenExpires { get; set; }
    public byte[]? ProfilePicture { get; set; }
    public string? ProfilePictureContentType { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public ICollection<FileRecord> Files { get; set; } = new List<FileRecord>();
    public ICollection<UserKeyPair> KeyPairs { get; set; } = new List<UserKeyPair>();
    public string Role { get; set; } = "User";
}
