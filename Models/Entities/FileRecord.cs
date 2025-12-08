using System;
using System.Runtime.CompilerServices;

// This is what we keep for each file in memory.
// It includes the bytes (the actual file) and some notes about it.
namespace FileFox_Backend.Models;

public class FileRecord
{
    public Guid Id { get; init; }
    public Guid UserId { get; set; }
    public required string FileName { get; init; } = string.Empty;
    public required string ContentType { get; init; } = string.Empty;
    public long Length { get; init; }
    public DateTimeOffset UploadedAt { get; init; } = DateTimeOffset.UtcNow;
    public required byte[] Bytes { get; init; } = Array.Empty<byte>();
}