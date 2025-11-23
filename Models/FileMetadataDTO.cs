using System;

// This is the info we show when listing files (no raw bytes).
namespace FileFox_Backend.Models;

public class FileMetadataDto
{
    public Guid Id { get; init; }
    public required string FileName { get; init; }
    public required string ContentType { get; init; }
    public long Length { get; init; }
    public DateTimeOffset UploadedAt { get; init; }
}