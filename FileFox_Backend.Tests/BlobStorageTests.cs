using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace FileFox_Backend.Tests;

public class BlobStorageTests
{
    private LocalBlobStorage GetBlobStorage()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection()
            .Build();

        return new LocalBlobStorage(config);
    }

    [Fact]
    public async Task PutAndGetChunk_Works()
    {
        var blob = GetBlobStorage();
        var fileId = Guid.NewGuid();
        var chunkData = Encoding.UTF8.GetBytes("test chunk data");

        using var ms = new MemoryStream(chunkData);
        var path = await blob.PutChunkAsync(fileId, 0, ms);
        Assert.True(File.Exists(path));

        using var retrieved = await blob.GetChunkAsync(fileId, 0);
        Assert.NotNull(retrieved);
        using var reader = new StreamReader(retrieved!);
        var text = await reader.ReadToEndAsync();
        Assert.Equal("test chunk data", text);
    }

    [Fact]
    public async Task PutAndGetManifest_Works()
    {
        var blob = GetBlobStorage();
        var fileId = Guid.NewGuid();
        var manifestData = Encoding.UTF8.GetBytes("manifest content");

        using var ms = new MemoryStream(manifestData);
        var path = await blob.PutManifestAsync(fileId, ms);
        Assert.True(File.Exists(path));

        using var retrieved = await blob.GetManifestAsync(fileId);
        Assert.NotNull(retrieved);
        using var reader = new StreamReader(retrieved!);
        var text = await reader.ReadToEndAsync();
        Assert.Equal("manifest content", text);
    }
}
