using System;

namespace FileFox_Backend.Core.Models;

public class BlobData
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FileId { get; set; }
    public int ChunkIndex { get; set; } // -1 for manifest
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
