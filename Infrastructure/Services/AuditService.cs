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

    public async Task LogFileActionAsync(Guid userId, Guid fileRecordId, string action)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            FileRecordId = fileRecordId,
            Action = action,
            Timestamp = DateTimeOffset.UtcNow
        });

        await _db.SaveChangesAsync();
    }

    public async Task LogActionAsync(Guid userId, string action)
    {
        _db.AuditLogs.Add(new AuditLog
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            FileRecordId = Guid.Empty,
            Action = action,
            Timestamp = DateTimeOffset.UtcNow
        });

        await _db.SaveChangesAsync();
    }
}