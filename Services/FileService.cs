using FileFox_Backend.Data;
using FileFox_Backend.Models;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Services;

public class FileService
{
    private readonly ApplicationDbContext _db;
    private readonly IBlobStorageService _blob;

    public FileService(ApplicationDbContext db, IBlobStorageService blob)
    {
        _db = db;
        _blob = blob;
    }

    public async Task<FileRecord> UploadAsync(Guid userId, IFormFile file)
    {
        if (file.Length == 0)
            throw new ArgumentException("File is empty", nameof(file));

        await using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        ms.Position = 0;

        // Save to local storage
        var path = await _blob.UploadFileAsync(ms, file.FileName, file.ContentType);

        var record = new FileRecord
        {
            UserId = userId,
            FileName = file.FileName,
            ContentType = file.ContentType,
            Length = file.Length,
            UploadedAt = DateTimeOffset.UtcNow,
            Bytes = null,
            FilePath = path
        };

        _db.Files.Add(record);
        await _db.SaveChangesAsync();

        return record;
    }

    public async Task<IEnumerable<FileRecord>> ListAsync(Guid userId)
    {
        return await _db.Files
            .AsNoTracking()
            .Where(f => f.UserId == userId)
            .OrderByDescending(f => f.UploadedAt)
            .ToListAsync();
    }

    public async Task<(Stream Stream, string FileName, string ContentType)?> DownloadAsync(Guid fileId, Guid userId)
    {
        var record = await _db.Files
            .AsNoTracking()
            .FirstOrDefaultAsync(f => f.Id == fileId && f.UserId == userId);

        if (record == null) return null;

        return await _blob.DownloadFileAsync(record.FilePath);
    }

    public async Task<bool> DeleteAsync(Guid fileId, Guid userId)
    {
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == fileId && f.UserId == userId);
        if (record == null) return false;

        if (File.Exists(record.FilePath))
            File.Delete(record.FilePath);

        _db.Files.Remove(record);
        await _db.SaveChangesAsync();

        return true;
    }

    public async Task ClearAsync(Guid userId)
    {
        var files = await _db.Files.Where(f => f.UserId == userId).ToListAsync();

        foreach (var file in files)
        {
            if (File.Exists(file.FilePath))
                File.Delete(file.FilePath);
        }

        _db.Files.RemoveRange(files);
        await _db.SaveChangesAsync();
    }
}
