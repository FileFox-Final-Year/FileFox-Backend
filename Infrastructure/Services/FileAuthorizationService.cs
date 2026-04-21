using FileFox_Backend.Core.Interfaces;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Infrastructure.Services;

public class FileAuthorizationService : IFileAuthorizationService
{
    private readonly ApplicationDbContext _db;

    public FileAuthorizationService(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<bool> IsOwner(Guid fileId, Guid userId)
    {
        return await _db.FileAccesses.AnyAsync(f =>
            f.FileRecordId == fileId &&
            f.UserId == userId &&
            f.Permissions == "owner" &&
            f.RevokedAt == null);
    }

    public async Task<bool> HasAccess(Guid fileId, Guid userId)
    {
        return await _db.FileAccesses.AnyAsync(f =>
            f.FileRecordId == fileId &&
            f.UserId == userId &&
            f.RevokedAt == null);
    }

    public async Task<bool> CanShare(Guid fileId, Guid userId)
    {
        // For now, only owners can share. Could be extended to allow shared users to share further.
        return await IsOwner(fileId, userId);
    }
}