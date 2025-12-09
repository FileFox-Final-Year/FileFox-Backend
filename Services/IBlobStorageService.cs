public interface IBlobStorageService
{
    Task<string> UploadFileAsync(Stream fileStream, string fileName, string contentType);
    Task<(Stream FileStream, string FileName, string ContentType)?> DownloadFileAsync(string filePath);
}