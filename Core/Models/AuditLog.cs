namespace FileFox_Backend.Core.Models;
public class AuditLog
{
    public Guid Id { get; set; }
    public Guid FileRecordId { get; set; }
    public Guid UserId { get; set; }
    public string Action { get; set; } = null!;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public FileRecord? FileRecord { get; set; }
}