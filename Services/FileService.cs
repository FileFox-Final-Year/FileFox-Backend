using FileFox_Backend.Data;
using FileFox_Backend.Models;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Services;

public class FileService
{
    private readonly ApplicationDbContext _db;
    private readonly IBlobStorageService _blob;
    private readonly ILogger<FileService> _logger;

    public FileService(ApplicationDbContext db, IBlobStorageService blob, ILogger<FileService> logger)
    {
        _db = db;
        _blob = blob;
        _logger = logger;
    }

    public async Task<FileRecord> UploadAsync(Guid userId, IFormFile file)
    {
        _logger.LogInformation("User {UserId} is uploading file {FileName}", userId, file.FileName);

        if (file.Length == 0)
        {
            _logger.LogWarning("User {UserId} tried to upload an empty file {FileName}", userId, file.FileName);
            throw new ArgumentException("File is empty", nameof(file));
        }

        await using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        ms.Position = 0;

        var path = await _blob.UploadFileAsync(ms, file.FileName, file.ContentType);

        var record = new FileRecord
        {
            UserId = userId,
            FileName = file.FileName,
            ContentType = file.ContentType,
            Length = file.Length,
            UploadedAt = DateTimeOffset.UtcNow,
            FilePath = path
        };

        // Add a placeholder FileKey
        var key = new FileKey
        {
            FileRecord = record,
            KeyName = "PLACEHOLDER",
            KeyValue = "PLACEHOLDER"
        };
        record.Keys.Add(key);

        _db.Files.Add(record);

        // Add AuditLog
        var log = new AuditLog
        {
            FileRecord = record,
            UserId = userId,
            Action = "Upload"
        };
        _db.AuditLogs.Add(log);

        await _db.SaveChangesAsync();

        _logger.LogInformation("File {FileName} uploaded successfully for user {UserId}", file.FileName, userId);
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
        var record = await _db.Files.AsNoTracking()
            .FirstOrDefaultAsync(f => f.Id == fileId && f.UserId == userId);

        if (record == null)
        {
            _logger.LogWarning("File {FileId} not found for user {UserId}", fileId, userId);
            return null;
        }

        _logger.LogInformation("User {UserId} downloading file {FileName}", userId, record.FileName);

        if (string.IsNullOrWhiteSpace(record.FilePath))
        {
            _logger.LogError("FilePath is NULL for FileId {FileId}", fileId);
            return null;
        }

        // Add AuditLog for download
        var log = new AuditLog
        {
            FileRecordId = record.Id,
            UserId = userId,
            Action = "Download"
        };
        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();

        return await _blob.DownloadFileAsync(record.FilePath);
    }

    public async Task<bool> DeleteAsync(Guid fileId, Guid userId)
    {
        var record = await _db.Files.FirstOrDefaultAsync(f => f.Id == fileId && f.UserId == userId);
        if (record == null) return false;

        if (File.Exists(record.FilePath))
            File.Delete(record.FilePath);

        // Add AuditLog for delete
        var log = new AuditLog
        {
            FileRecordId = record.Id,
            UserId = userId,
            Action = "Delete"
        };
        _db.AuditLogs.Add(log);

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

    public async Task<FileRecord?> GetFileRecordAsync(Guid fileId)
    {
        return await _db.Files
            .AsNoTracking()
            .FirstOrDefaultAsync(f => f.Id == fileId);
    }
}
