using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

public class LocalBlobStorage : IBlobStorageService
{
    private readonly string _storageRoot;

    public LocalBlobStorage(IConfiguration config)
    {
        _storageRoot = config["LocalStorage:Path"] ?? "EncryptedFiles";
        Directory.CreateDirectory(_storageRoot);
    }

    private string FileDir(Guid fileId)
        => Path.Combine(_storageRoot, fileId.ToString());

    public async Task<string> PutChunkAsync(Guid fileId, int index, Stream ciphertext)
    {
        var dir = FileDir(fileId);
        Directory.CreateDirectory(dir);

        var path = Path.Combine(dir, $"chunk_{index:D6}");
        await using var fs = File.Create(path);
        await ciphertext.CopyToAsync(fs);

        return path;
    }

    public Task<Stream?> GetChunkAsync(Guid fileId, int index)
    {
        var path = Path.Combine(FileDir(fileId), $"chunk_{index:D6}");
        if (!File.Exists(path)) return Task.FromResult<Stream?>(null);

        return Task.FromResult<Stream?>(File.OpenRead(path));
    }

    public async Task<string> PutManifestAsync(Guid fileId, Stream encryptedManifest)
    {
        var dir = FileDir(fileId);
        Directory.CreateDirectory(dir);

        var path = Path.Combine(dir, "manifest");
        await using var fs = File.Create(path);
        await encryptedManifest.CopyToAsync(fs);

        return path;
    }

    public Task<Stream?> GetManifestAsync(Guid fileId)
    {
        var path = Path.Combine(FileDir(fileId), "manifest");
        if (!File.Exists(path)) return Task.FromResult<Stream?>(null);

        return Task.FromResult<Stream?>(File.OpenRead(path));
    }
}