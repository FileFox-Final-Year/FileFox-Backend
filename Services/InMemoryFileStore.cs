// This is our in-memory file store implementation. It keeps files in RAM while the app is running.
using System;
using System.Collections.Concurrent;
using FileFox_Backend.Models;

namespace FileFox_Backend.Services;

public class InMemoryFileStore : IFileStore
{
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, FileRecord>> _store = new();

    // Save a file for a specific user
    public async Task<Guid> SaveAsync(Guid userId, IFormFile file, CancellationToken cancellationToken = default)
    {
        if (file is null || file.Length == 0)
            throw new ArgumentException("File is null or empty", nameof(file));

        using var ms = new MemoryStream();
        await file.CopyToAsync(ms, cancellationToken);
        var bytes = ms.ToArray();

        var id = Guid.NewGuid();
        var record = new FileRecord
        {
            Id = id,
            FileName = file.FileName,
            ContentType = string.IsNullOrWhiteSpace(file.ContentType) ? "application/octet-stream" : file.ContentType,
            Length = file.Length,
            UploadedAt = DateTimeOffset.UtcNow,
            Bytes = bytes
        };

        var files = _store.GetOrAdd(userId, _ => new());
        files[id] = record;
        return id;
    }

    // List all files for a user
    public IEnumerable<FileRecord> List(Guid userId)
        => _store.TryGetValue(userId, out var files)
            ? files.Values.OrderByDescending(f => f.UploadedAt)
            : Enumerable.Empty<FileRecord>();

    // ind one file for a user
    public bool TryGet(Guid userId, Guid id, out FileRecord record)
    {
        record = default!;
        return _store.TryGetValue(userId, out var files) && files.TryGetValue(id, out record!);
    }

    // Delete one file for a user
    public bool Delete(Guid userId, Guid id)
        => _store.TryGetValue(userId, out var files) && files.TryRemove(id, out _);

    // Delete all files for a user
    public void Clear(Guid userId)
    {
        if (_store.TryGetValue(userId, out var files))
            files.Clear();
    }
}