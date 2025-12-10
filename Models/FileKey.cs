namespace FileFox_Backend.Models;
public class FileKey
{
    public Guid Id { get; set; }
    public Guid FileRecordId { get; set; }
    public string KeyName { get; set; } = null!;
    public string KeyValue { get; set; } = null!;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public FileRecord FileRecord { get; set; } = null!;
}