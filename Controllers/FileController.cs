using System.Security.Claims;
using FileFox_Backend.Models;
using FileFox_Backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileFox_Backend.Controllers;

[ApiController]
[Route("files")]
[Authorize]
public class FilesController : ControllerBase
{
    private readonly FileService _fileService;
    private readonly ILogger<FilesController> _logger;
    private readonly IAuthorizationService _authorizationService;

    public FilesController(
        FileService fileService, 
        ILogger<FilesController> logger,
        IAuthorizationService authorizationService)
    {
        _fileService = fileService;
        _logger = logger;
        _authorizationService = authorizationService;
    }

    // -------------------- UPLOAD --------------------
    [HttpPost]
    [Consumes("multipart/form-data")]
    [RequestSizeLimit(long.MaxValue)]
    [ProducesResponseType(typeof(object), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Upload([FromForm] UploadFileRequest form, CancellationToken ct)
    {
        var file = form.File;
        if (file is null) return BadRequest(new { error = "Missing file" });
        if (file.Length == 0) return BadRequest(new { error = "File is empty" });

        try
        {
            var userId = GetUserId();
            var record = await _fileService.UploadAsync(userId, file);
            var location = Url.Action(nameof(Download), new { id = record.Id }) ?? $"/files/{record.Id}";
            return Created(location, new { id = record.Id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to upload file {File}", file.FileName);
            return Problem("Failed to upload file");
        }
    }

    // -------------------- LIST FILES --------------------
    [HttpGet]
    [ProducesResponseType(typeof(IEnumerable<FileMetadataDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> List()
    {
        var userId = GetUserId();
        var items = await _fileService.ListAsync(userId);

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

    // -------------------- DOWNLOAD --------------------
    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Download([FromRoute] Guid id, [FromQuery] bool attachment = true)
    {
        var fileRecord = await _fileService.GetFileRecordAsync(id);
        if (fileRecord == null) return NotFound();

        // Enforce policy: FileOwner or Admin
        var authResult = await _authorizationService.AuthorizeAsync(User, fileRecord, "FileOwnerPolicy");
        if (!authResult.Succeeded) return Forbid();

        var result = await _fileService.DownloadAsync(fileRecord.Id, fileRecord.UserId);
        if (result == null) return NotFound();

        return File(result.Value.Stream, result.Value.ContentType, attachment ? result.Value.FileName : null);
    }

    // -------------------- DELETE --------------------
    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Delete([FromRoute] Guid id)
    {
        var fileRecord = await _fileService.GetFileRecordAsync(id);
        if (fileRecord == null) return NotFound();

        var authResult = await _authorizationService.AuthorizeAsync(User, fileRecord, "FileOwnerPolicy");
        if (!authResult.Succeeded) return Forbid();

        await _fileService.DeleteAsync(fileRecord.Id, fileRecord.UserId);
        return NoContent();
    }

    // -------------------- CLEAR USER FILES --------------------
    [HttpDelete]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Clear()
    {
        var userId = GetUserId();
        await _fileService.ClearAsync(userId);
        return NoContent();
    }

    // -------------------- HELPER --------------------
    private Guid GetUserId()
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        return Guid.Parse(sub!);
    }
}
