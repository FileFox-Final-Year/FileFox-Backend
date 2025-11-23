using Microsoft.AspNetCore.Http;

// This matches the form data for uploads.
// It has one field named "file".
namespace FileFox_Backend.Models;

public class UploadFileRequest
{
    public IFormFile? File { get; set; }
}