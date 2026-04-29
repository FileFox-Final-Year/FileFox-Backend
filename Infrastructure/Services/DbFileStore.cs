using FileFox_Backend.Core.Interfaces;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
namespace FileFox_Backend.Infrastructure.Services;

public class DbFileStore : IFileStore
{
    private readonly ApplicationDbContext _db;
    private readonly IBlobStorageService _blob;

    public DbFileStore(ApplicationDbContext db, IBlobStorageService blob)
    {
        _db = db;
        _blob = blob;
    }

    public async Task<Guid> SaveAsync(Guid userId, IFormFile file, string? encryptedMetadata = null, string? recoveryWrappedKey = null, string? wrappedFileKey = null, CancellationToken ct = default)
    {
        var fileId = Guid.NewGuid();

        await using var stream = file.OpenReadStream();
        await _blob.PutChunkAsync(fileId, 0, stream);

        var record = new FileRecord
        {
            Id = fileId,
            UserId = userId,
            EncryptedFileName = file.FileName,
            EncryptedMetadata = encryptedMetadata,
            ContentType = file.ContentType,
            TotalSize = file.Length,
            ChunkSize = (int)file.Length,
            CryptoVersion = "v1-simple",
            ManifestBlobPath = string.Empty,
            UploadedAt = DateTimeOffset.UtcNow,
            RecoveryWrappedKey = recoveryWrappedKey
        };

        _db.Files.Add(record);

        if (!string.IsNullOrEmpty(wrappedFileKey))
        {
            _db.FileKeys.Add(new FileKey
            {
                FileRecordId = fileId,
                WrappedFileKey = wrappedFileKey
            });
        }

        await _db.SaveChangesAsync(ct);

        return fileId;
    }

    public async Task<IEnumerable<FileRecord>> ListAsync(Guid userId, CancellationToken ct = default)
    {
        return await _db.Files
            .Include(f => f.Keys)
            .Where(f => f.UserId == userId)
            .ToListAsync(ct);
    }

    public async Task<FileRecord?> GetAsync(Guid userId, Guid fileId)
    {
        return await _db.Files
            .Include(f => f.Keys)
            .FirstOrDefaultAsync(f => f.UserId == userId && f.Id == fileId);
    }

    public async Task<bool> DeleteAsync(Guid userId, Guid fileId)
    {
        var record = await GetAsync(userId, fileId);
        if (record == null) return false;

        // Delete associated blobs first
        await _blob.DeleteAllChunksAsync(fileId);

        _db.Files.Remove(record);
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task ClearAsync(Guid userId)
    {
        var files = await _db.Files.Where(f => f.UserId == userId).ToListAsync();
        _db.Files.RemoveRange(files);
        await _db.SaveChangesAsync();
    }
}
