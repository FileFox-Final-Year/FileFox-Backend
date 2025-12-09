using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

public class LocalBlobStorage : IBlobStorageService
{
    private readonly string _storageRoot;

    public LocalBlobStorage(IConfiguration config)
    {
        _storageRoot = config["LocalStorage:Path"] ?? "LocalFiles";
        if (!Directory.Exists(_storageRoot))
            Directory.CreateDirectory(_storageRoot);
    }

    public async Task<string> UploadFileAsync(Stream fileStream, string fileName, string contentType)
    {
        var id = Guid.NewGuid();
        var path = Path.Combine(_storageRoot, id.ToString());

        await using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        await fileStream.CopyToAsync(fs);

        return path;
    }

    public async Task<(Stream FileStream, string FileName, string ContentType)?> DownloadFileAsync(string filePath)
    {
        if (!File.Exists(filePath)) return null;

        var fileName = Path.GetFileName(filePath);
        var memoryStream = new MemoryStream();
        await using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            await fs.CopyToAsync(memoryStream);
        }
        memoryStream.Position = 0;

        return (memoryStream, fileName, "application/octet-stream");
    }
}
