namespace FileFox_Backend.Core.Models;
public class FileAccess
{
    public Guid Id { get; set; }
    public Guid FileRecordId { get; set; }
    public FileRecord FileRecord { get; set; } = null!;
    public Guid UserId { get; set; }
    public string WrappedDek { get; set; } = null!;
    public string Permissions { get; set; } = null!; // e.g. "read", "write"
    public int KeyVersion { get; set; } // For future key rotation
    public DateTime CreatedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public int FileEncryptionVersion { get; set; } = 1;

}