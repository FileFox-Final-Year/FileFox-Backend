using FileFox_Backend.Core.Interfaces;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace FileFox_Backend.Infrastructure.Services;

public class SqlBlobStorage : IBlobStorageService
{
    private readonly ApplicationDbContext _db;

    public SqlBlobStorage(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<string> PutChunkAsync(Guid fileId, int chunkIndex, Stream ciphertext)
    {
        using var ms = new MemoryStream();
        await ciphertext.CopyToAsync(ms);
        var data = ms.ToArray();

        var blob = await _db.Blobs.FirstOrDefaultAsync(b => b.FileId == fileId && b.ChunkIndex == chunkIndex);
        if (blob == null)
        {
            blob = new BlobData
            {
                FileId = fileId,
                ChunkIndex = chunkIndex,
                Data = data
            };
            _db.Blobs.Add(blob);
        }
        else
        {
            blob.Data = data;
            _db.Blobs.Update(blob);
        }

        await _db.SaveChangesAsync();
        return $"sql:{fileId}:{chunkIndex}";
    }

    public async Task<Stream?> GetChunkAsync(Guid fileId, int chunkIndex)
    {
        var blob = await _db.Blobs.FirstOrDefaultAsync(b => b.FileId == fileId && b.ChunkIndex == chunkIndex);
        if (blob == null) return null;

        return new MemoryStream(blob.Data);
    }

    public async Task<string> PutManifestAsync(Guid fileId, Stream encryptedManifest)
    {
        return await PutChunkAsync(fileId, -1, encryptedManifest);
    }

    public async Task<Stream?> GetManifestAsync(Guid fileId)
    {
        return await GetChunkAsync(fileId, -1);
    }

    public async Task DeleteAllChunksAsync(Guid fileId)
    {
        var blobs = await _db.Blobs.Where(b => b.FileId == fileId).ToListAsync();
        _db.Blobs.RemoveRange(blobs);
        await _db.SaveChangesAsync();
    }
}
