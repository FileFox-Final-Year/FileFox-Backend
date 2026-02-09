using System;
using System.IO;
using System.Threading.Tasks;

public interface IBlobStorageService
{
    Task<string> PutChunkAsync(Guid fileId, int chunkIndex, Stream ciphertext);
    Task<Stream?> GetChunkAsync(Guid fileId, int chunkIndex);
    Task<string> PutManifestAsync(Guid fileId, Stream encryptedManifest);
    Task<Stream?> GetManifestAsync(Guid fileId);
}