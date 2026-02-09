using System.Security.Claims;
using FileFox_Backend.Models;
using FileFox_Backend.Extensions;
using FileFox_Backend.Services;
using FileFox_Backend.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Authorize]
public class FilesController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly IBlobStorageService _blob;

    public FilesController(ApplicationDbContext db, IBlobStorageService blob)
    {
        _db = db;
        _blob = blob;
    }
    
     // ---------------- INIT UPLOAD ----------------
    [HttpPost("init")]
    public async Task<IActionResult> Init([FromBody] InitUploadDto dto)
    {
        var userId = User.GetUserId();
        var fileId = Guid.NewGuid();

        var record = new FileRecord
        {
            Id = fileId,
            UserId = userId,
            EncryptedFileName = dto.EncryptedFileName,
            ChunkSize = dto.ChunkSize,
            CryptoVersion = dto.CryptoVersion
        };

        var key = new FileKey
        {
            FileRecordId = fileId,
            WrappedFileKey = dto.WrappedFileKey
        };

        _db.Files.Add(record);
        _db.FileKeys.Add(key);
        await _db.SaveChangesAsync();

        // store encrypted manifest header
        var headerBytes = Convert.FromBase64String(dto.EncryptedManifestHeader);
        await using var memoryStream = new MemoryStream(headerBytes);
        record.ManifestBlobPath = await _blob.PutManifestAsync(fileId, memoryStream);

        await _db.SaveChangesAsync();

        return Ok(new { fileId });
    }

    // ---------------- UPLOAD CHUNK ----------------
    [HttpPut("{id:guid}/chunks/{index:int}")]
    public async Task<IActionResult> UploadChunk(Guid id, int index)
    {
        await _blob.PutChunkAsync(id, index, Request.Body);
        return Ok();
    }

    // ---------------- COMPLETE UPLOAD ----------------
    [HttpPost("{id:guid}/complete")]
    public IActionResult Complete(Guid id)
    {
        return Ok();
    }
}
