using System;

namespace FileFox_Backend.Models;

public class FileRecord
{
    public Guid Id { get; init; }
    public Guid UserId { get; set; }
    public required string FileName { get; init; } = string.Empty;
    public required string ContentType { get; init; } = string.Empty;
    public long Length { get; init; }
    public DateTimeOffset UploadedAt { get; init; } = DateTimeOffset.UtcNow;
    public byte[]? Bytes { get; set; }
    public string? FilePath { get; set; }
}

