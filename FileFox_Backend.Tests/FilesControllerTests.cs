using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using FileFox_Backend.Controllers;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Services;
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
        var blob = new SqlBlobStorage(db);
        var fileStore = new DbFileStore(db, blob);
        var audit = new AuditService(db);
        var controller = new FilesController(db, blob, fileStore, audit);

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

        Assert.NotNull(await blob.GetManifestAsync((Guid)fileId));
    }

    [Fact]
    public async Task GetMetadata_IncludesKeys()
    {
        using var db = GetInMemoryDb();
        var blob = new SqlBlobStorage(db);
        var fileStore = new DbFileStore(db, blob);
        var audit = new AuditService(db);
        var controller = new FilesController(db, blob, fileStore, audit);

        var userId = Guid.NewGuid();
        var fileId = Guid.NewGuid();
        db.Files.Add(new FileRecord { Id = fileId, UserId = userId, EncryptedFileName = "test.bin", ManifestBlobPath = "path" });
        db.FileKeys.Add(new FileKey { FileRecordId = fileId, WrappedFileKey = "key123" });
        await db.SaveChangesAsync();

        controller.ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(new[]
                    {
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, userId.ToString())
                    }, "TestAuth")
                )
            }
        };

        var result = await controller.GetMetadata(fileId);
        var okResult = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(result);
        var dto = Assert.IsType<FileMetadataDto>(okResult.Value);

        Assert.Equal("test.bin", dto.FileName);
        Assert.Single(dto.WrappedKeys);
        Assert.Equal("key123", dto.WrappedKeys[0]);
    }

    [Fact]
    public async Task Download_ReturnsFileStream_ForSimpleFile()
    {
        using var db = GetInMemoryDb();
        var blob = new SqlBlobStorage(db);
        var fileStore = new DbFileStore(db, blob);
        var audit = new AuditService(db);
        var controller = new FilesController(db, blob, fileStore, audit);

        var userId = Guid.NewGuid();
        var fileId = Guid.NewGuid();

        db.Files.Add(new FileRecord
        {
            Id = fileId,
            UserId = userId,
            EncryptedFileName = "test.bin",
            ManifestBlobPath = "path",
            CryptoVersion = "v1-simple",
            ContentType = "application/octet-stream"
        });
        await db.SaveChangesAsync();

        // Put a chunk
        await blob.PutChunkAsync(fileId, 0, new MemoryStream(Encoding.UTF8.GetBytes("hello world")));

        controller.ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(new[]
                    {
                        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, userId.ToString())
                    }, "TestAuth")
                )
            }
        };

        var result = await controller.Download(fileId);
        var fileResult = Assert.IsType<Microsoft.AspNetCore.Mvc.FileStreamResult>(result);
        Assert.Equal("application/octet-stream", fileResult.ContentType);
        Assert.Equal("test.bin", fileResult.FileDownloadName);

        using var ms = new MemoryStream();
        await fileResult.FileStream.CopyToAsync(ms);
        Assert.Equal("hello world", Encoding.UTF8.GetString(ms.ToArray()));
    }
}
