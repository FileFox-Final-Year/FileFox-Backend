using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;

namespace FileFox_Backend.Infrastructure.Services;

public class AuditService
{
    private readonly ApplicationDbContext _db;

    public AuditService(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task LogAsync(Guid userId, string action, Guid? fileId = null)
    {
        var log = new AuditLog
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Action = action,
            FileRecordId = fileId,
            Timestamp = DateTimeOffset.UtcNow
        };

        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();
    }
}
