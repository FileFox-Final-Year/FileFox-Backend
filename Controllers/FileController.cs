using System.Security.Claims;
using FileFox_Backend.Models;
using FileFox_Backend.Extensions;
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
    private readonly IAuthorizationService _authorizationService;

    public FilesController(
        FileService fileService,
        IAuthorizationService authorizationService)
    {
        _fileService = fileService;
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
        if (form.File == null || form.File.Length == 0)
            return BadRequest(new { error = "File is required" });

        var userId = User.GetUserId();
        var record = await _fileService.UploadAsync(userId, form.File);

        return Created($"/files/{record.Id}", new { record.Id });
    }

    // -------------------- LIST FILES --------------------
    [HttpGet]
    [ProducesResponseType(typeof(IEnumerable<FileMetadataDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> List()
    {
        var userId = User.GetUserId();
        return Ok(await _fileService.ListAsync(userId));
    }

    // -------------------- DOWNLOAD --------------------
    [HttpGet("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Download([FromRoute] Guid id, [FromQuery] bool attachment = true)
    {
        var record = await _fileService.GetFileRecordAsync(id);
        if (record == null) return NotFound();

        var auth = await _authorizationService.AuthorizeAsync(User, record, "FileOwnerPolicy");
        if (!auth.Succeeded) return Forbid();

        var file = await _fileService.DownloadAsync(record.Id, record.UserId);
        return File(file!.Value.Stream, file.Value.ContentType, file.Value.FileName);
    }

    // -------------------- DELETE --------------------
    [HttpDelete("{id:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Delete([FromRoute] Guid id)
    {
        var record = await _fileService.GetFileRecordAsync(id);
        if (record == null) return NotFound();

        var auth = await _authorizationService.AuthorizeAsync(User, record, "FileOwnerPolicy");
        if (!auth.Succeeded) return Forbid();

        await _fileService.DeleteAsync(record.Id, record.UserId);
        return NoContent();
    }
}
