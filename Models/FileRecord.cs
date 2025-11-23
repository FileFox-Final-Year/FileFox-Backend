using System;

// This is what we keep for each file in memory.
// It includes the bytes (the actual file) and some notes about it.
namespace FileFox_Backend.Models;

public class FileRecord
{
    public Guid Id { get; init; }
    public required string FileName { get; init; }
    public required string ContentType { get; init; }
    public long Length { get; init; }
    public DateTimeOffset UploadedAt { get; init; }
    public required byte[] Bytes { get; init; }
}