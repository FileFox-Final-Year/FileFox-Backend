using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using FileFox_Backend.Controllers;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Services;
using FileFox_Backend.Infrastructure.Results;
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
        var fileStore = new LocalFileStore(db, blob);
        var auditService = new AuditService(db);
        var manifestService = new ManifestService();
        var authService = new FileAuthorizationService(db);
        var controller = new FilesController(db, blob, fileStore, auditService, manifestService, authService);

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

    [Fact]
    public async Task GetMetadata_IncludesKeys()
    {
        using var db = GetInMemoryDb();
        var blob = new LocalBlobStorage(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build());
        var fileStore = new LocalFileStore(db, blob);
        var auditService = new AuditService(db);
        var manifestService = new ManifestService();
        var authService = new FileAuthorizationService(db);
        var controller = new FilesController(db, blob, fileStore, auditService, manifestService, authService);

        var userId = Guid.NewGuid();
        var fileId = Guid.NewGuid();

        // Add file
        db.Files.Add(new FileRecord 
        { 
            Id = fileId, 
            UserId = userId, 
            EncryptedFileName = "test.bin", 
            ManifestBlobPath = "path",
            FileEncryptionVersion = 1
        });

        // Add user access (important!)
        db.FileAccesses.Add(new FileFox_Backend.Core.Models.FileAccess
        {
            FileRecordId = fileId,
            UserId = userId,
            Permissions = "owner", // <-- REQUIRED
            WrappedDek = "key123",
            KeyVersion = 1,
            FileEncryptionVersion = 1,
            CreatedAt = DateTime.UtcNow
        });

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
        var blob = new LocalBlobStorage(new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build());
        var fileStore = new LocalFileStore(db, blob);
        var auditService = new AuditService(db);
        var manifestService = new ManifestService();
        var authService = new FileAuthorizationService(db);
        var controller = new FilesController(db, blob, fileStore, auditService, manifestService, authService);

        var userId = Guid.NewGuid();
        var fileId = Guid.NewGuid();

        db.Files.Add(new FileRecord
        {
            Id = fileId,
            UserId = userId,
            EncryptedFileName = "test.bin",
            ManifestBlobPath = "path",
            CryptoVersion = "v1-simple",
            ContentType = "application/octet-stream",
            FileEncryptionVersion = 1
        });

        // Add user access
        db.FileAccesses.Add(new FileFox_Backend.Core.Models.FileAccess
        {
            FileRecordId = fileId,
            UserId = userId,
            Permissions = "owner", // <-- REQUIRED
            WrappedDek = "key1",
            KeyVersion = 1,
            FileEncryptionVersion = 1,
            CreatedAt = DateTime.UtcNow,
            RevokedAt = null
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
        var fileResult = Assert.IsType<FileCallbackResult>(result);
        Assert.Equal("application/octet-stream", fileResult.ContentType);
        Assert.Equal($"file-{fileId}", fileResult.FileDownloadName);
    }
}