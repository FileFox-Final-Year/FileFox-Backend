using System;

namespace FileFox_Backend.Core.Models;
public class UserKeyPair
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string Algorithm { get; set; } = null!;
    public string PublicKey { get; set; } = null!;
    public string EncryptedPrivateKey { get; set; } = null!;
    public int KeyVersion { get; set; } = 1;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? RevokedAt { get; set; }
    public User User { get; set; } = null!;
}   