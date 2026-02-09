using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using FileFox_Backend.Controllers;
using FileFox_Backend.Data;
using FileFox_Backend.Models;
using FileFox_Backend.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FileFox_Backend.Tests;

public class FilesControllerTests
{
    private ApplicationDbContext GetInMemoryDb()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new ApplicationDbContext(options);
    }

    [Fact]
    public async Task InitUpload_CreatesFileRecordAndManifest()
    {
        using var db = GetInMemoryDb();
        var blob = new LocalBlobStorage(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build());
        var controller = new FilesController(db, blob);

        // Mock user identity
        var userId = Guid.NewGuid().ToString();
        controller.ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(new[]
                    {
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, userId)
                    }, "TestAuth")
                )
            }
        };

        var dto = new InitUploadDto
        {
            EncryptedFileName = "encryptedName",
            ChunkSize = 4096,
            CryptoVersion = "v1",
            EncryptedManifestHeader = Convert.ToBase64String(Encoding.UTF8.GetBytes("dummy manifest")),
            WrappedFileKey = "wrappedKey"
        };

        var result = await controller.Init(dto);

        Assert.NotNull(result);

        var okResult = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(result);
        var fileIdProp = okResult.Value!.GetType().GetProperty("fileId")!;
        var fileId = (Guid)fileIdProp.GetValue(okResult.Value)!;

        var record = await db.Files.FindAsync((Guid)fileId);
        Assert.NotNull(record);
        Assert.Equal(dto.EncryptedFileName, record.EncryptedFileName);
        Assert.False(string.IsNullOrEmpty(record.ManifestBlobPath));

        Assert.True(File.Exists(record.ManifestBlobPath));
    }
}
