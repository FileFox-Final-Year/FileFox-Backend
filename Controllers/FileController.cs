using System.Security.Claims;
using FileFox_Backend.Models;
using FileFox_Backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Microsoft.AspNetCore.Authorization.Authorize] // Only logged-in users can use these file roads
public class FilesController(IFileStore store, ILogger<FilesController> logger) : ControllerBase
{
    private readonly IFileStore _store = store;
    private readonly ILogger<FilesController> _logger = logger;

    // Upload a file and save it
    [HttpPost]
    [Consumes("multipart/form-data")]
    [RequestSizeLimit(long.MaxValue)]
    [ProducesResponseType(typeof(object), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Upload([FromForm] UploadFileRequest form, CancellationToken ct)
    {
        var file = form.File;
        if (file is null)
            return BadRequest(new { error = "Missing form file field 'file'" });

        if (file.Length == 0)
            return BadRequest(new { error = "File is empty" });

        try
        {
            var userId = GetUserId();
            var id = await _store.SaveAsync(userId, file, ct);
            var location = Url.Action(nameof(Download), new { id }) ?? $"/files/{id}";
            return Created(location, new { id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to upload file {File}", file.FileName);
            return Problem("Failed to upload file");
        }
    }

    // List all the files that belong to you
    [HttpGet]
    [ProducesResponseType(typeof(IEnumerable<FileMetadataDto>), StatusCodes.Status200OK)]
    public IActionResult List()
    {
        var userId = GetUserId();
        var items = _store.List(userId)
            .Select(f => new FileMetadataDto
            {
                Id = f.Id,
                FileName = f.FileName,
                ContentType = f.ContentType,
                Length = f.Length,
                UploadedAt = f.UploadedAt
            });
        return Ok(items);
    }

    // Download one of your files by its id
    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult Download([FromRoute] Guid id, [FromQuery] bool attachment = true)
    {
        var userId = GetUserId();
        if (!_store.TryGet(userId, id, out var record))
            return NotFound();

        var fileResult = File(record.Bytes, record.ContentType, attachment ? record.FileName : null);
        return fileResult;
    }

    // Delete one of your files by its id
    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public IActionResult Delete([FromRoute] Guid id)
    {
        var userId = GetUserId();
        return _store.Delete(userId, id) ? NoContent() : NotFound();
    }

    // Delete ALL of your files
    [HttpDelete]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public IActionResult Clear()
    {
        var userId = GetUserId();
        _store.Clear(userId);
        return NoContent();
    }

    // Find out who you are from the token (your name tag)
    private Guid GetUserId()
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        return Guid.Parse(sub!);
    }
}