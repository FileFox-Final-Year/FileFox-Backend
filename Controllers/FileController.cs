using System.Security.Claims;
using FileFox_Backend.Models;
using FileFox_Backend.Services;
using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Microsoft.AspNetCore.Authorization.Authorize] // Only logged-in users can access
public class FilesController : ControllerBase
{
    private readonly IFileStore _store;
    private readonly ILogger<FilesController> _logger;

    public FilesController(IFileStore store, ILogger<FilesController> logger)
    {
        _store = store;
        _logger = logger;
    }

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

    // List all files that belong to the current user
    [HttpGet]
    [ProducesResponseType(typeof(IEnumerable<FileMetadataDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var userId = GetUserId();
        var items = await _store.ListAsync(userId, ct);

        var dto = items.Select(f => new FileMetadataDto
        {
            Id = f.Id,
            FileName = f.FileName,
            ContentType = f.ContentType,
            Length = f.Length,
            UploadedAt = f.UploadedAt
        });

        return Ok(dto);
    }

    // Download a single file by ID
    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Download([FromRoute] Guid id, [FromQuery] bool attachment = true)
    {
        var userId = GetUserId();
        var record = await _store.GetAsync(userId, id);
        if (record is null)
            return NotFound();

        return File(record.Bytes, record.ContentType, attachment ? record.FileName : null);
    }

    // Delete a file by ID
    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete([FromRoute] Guid id)
    {
        var userId = GetUserId();
        var success = await _store.DeleteAsync(userId, id);
        return success ? NoContent() : NotFound();
    }

    // Delete all files for the current user
    [HttpDelete]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Clear()
    {
        var userId = GetUserId();
        await _store.ClearAsync(userId);
        return NoContent();
    }

    // Helper: get the current user ID from JWT
    private Guid GetUserId()
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        return Guid.Parse(sub!);
    }
}
