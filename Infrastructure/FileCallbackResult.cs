using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace FileFox_Backend.Infrastructure;

public class FileCallbackResult : ActionResult
{
    private readonly Func<Stream, ActionContext, Task> _callback;

    public string ContentType { get; }
    public string? FileDownloadName { get; init; }

    public FileCallbackResult(string contentType, Func<Stream, ActionContext, Task> callback)
    {
        ContentType = contentType;
        _callback = callback;
    }

    public override async Task ExecuteResultAsync(ActionContext context)
    {
        var response = context.HttpContext.Response;
        response.ContentType = ContentType;

        if (!string.IsNullOrEmpty(FileDownloadName))
        {
            var contentDisposition = new ContentDispositionHeaderValue("attachment");
            contentDisposition.SetHttpFileName(FileDownloadName);
            response.Headers[HeaderNames.ContentDisposition] = contentDisposition.ToString();
        }

        using var outputStream = response.Body;
        await _callback(outputStream, context);
    }
}
