using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace FileFox_Backend.Infrastructure.Results;

public class FileCallbackResult : FileResult
{
    private readonly Func<Stream, HttpContext, Task> _callback;

    public FileCallbackResult(string contentType, Func<Stream, HttpContext, Task> callback)
        : base(contentType)
    {
        _callback = callback ?? throw new ArgumentNullException(nameof(callback));
    }

    public override async Task ExecuteResultAsync(ActionContext context)
    {
        if (context == null)
            throw new ArgumentNullException(nameof(context));

        var httpContext = context.HttpContext;
        var response = httpContext.Response;

        if (!string.IsNullOrEmpty(FileDownloadName))
        {
            var headerValue = new ContentDispositionHeaderValue("attachment")
            {
                FileNameStar = FileDownloadName
            };
            response.Headers[HeaderNames.ContentDisposition] = headerValue.ToString();
        }

        response.ContentType = ContentType ?? "application/octet-stream";

        await _callback(response.Body, httpContext);
    }
}
