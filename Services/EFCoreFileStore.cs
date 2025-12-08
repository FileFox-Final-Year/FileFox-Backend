using FileFox_Backend.Data;
using FileFox_Backend.Models;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Services;

public class EFCoreFileStore : IFileStore
{
    private readonly ApplicationDbContext _db;

    public EFCoreFileStore(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<Guid> SaveAsync(Guid userId, IFormFile file, CancellationToken ct = default)
    {
        if (file == null || file.Length == 0)
            throw new ArgumentException("File is empty", nameof(file));

        await using var ms = new MemoryStream();
        await file.CopyToAsync(ms, ct);

        var record = new FileRecord
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            FileName = file.FileName,
            ContentType = file.ContentType,
            Length = file.Length,
            UploadedAt = DateTimeOffset.UtcNow,
            Bytes = ms.ToArray()
        };

        _db.Files.Add(record);
        await _db.SaveChangesAsync(ct);

        return record.Id;
    }

    public async Task<IEnumerable<FileRecord>> ListAsync(Guid userId, CancellationToken ct = default)
    {
        return await _db.Files
            .AsNoTracking()
            .Where(f => f.UserId == userId)
            .OrderByDescending(f => f.UploadedAt)
            .ToListAsync(ct);
    }

    public async Task<FileRecord?> GetAsync(Guid userId, Guid fileId)
    {
        return await _db.Files
            .AsNoTracking()
            .FirstOrDefaultAsync(f => f.UserId == userId && f.Id == fileId);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid fileId)
    {
        var record = await _db.Files.FirstOrDefaultAsync(f => f.UserId == userId && f.Id == fileId);
        if (record == null) return false;

        _db.Files.Remove(record);
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task ClearAsync(Guid userId)
    {
        var files = _db.Files.Where(f => f.UserId == userId);
        _db.Files.RemoveRange(files);
        await _db.SaveChangesAsync();
    }
}
