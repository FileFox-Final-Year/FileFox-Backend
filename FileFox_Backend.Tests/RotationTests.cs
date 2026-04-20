using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using FileFox_Backend.Controllers;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FileFox_Backend.Tests.Phase6;

public class RotationTests
{
    private ApplicationDbContext GetDb()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new ApplicationDbContext(options);
    }

    private ClaimsPrincipal CreateUser(Guid userId)
    {
        return new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("sub", userId.ToString())
        }, "test"));
    }

    [Fact]
    public async Task Owner_Can_Rotate_File()
    {
        await using var db = GetDb();

        var ownerId = Guid.NewGuid();
        var fileId = Guid.NewGuid();

        db.Files.Add(new FileRecord
        {
            Id = fileId,
            UserId = ownerId,
            EncryptedFileName = "file.txt",
            ManifestBlobPath = "manifest/path",
            UploadedAt = DateTime.UtcNow,
            ContentType = "application/octet-stream",
            CryptoVersion = "v1-simple",
            FileEncryptionVersion = 1
        });

        db.FileAccesses.Add(new FileAccess
        {
            FileRecordId = fileId,
            UserId = ownerId,
            Permissions = "owner",
            WrappedDek = "key-v1",
            KeyVersion = 1,
            FileEncryptionVersion = 1,
            CreatedAt = DateTime.UtcNow,
            RevokedAt = null
        });

        await db.SaveChangesAsync();

        var controller = new FilesController(db, null!, null!)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = CreateUser(ownerId)
                }
            }
        };

        var request = new FilesController.RotateRequest
        {
            Members = new()
            {
                new FilesController.RotateMember
                {
                    UserId = ownerId,
                    WrappedDek = "key-v2",
                    KeyVersion = 2
                }
            }
        };

        var result = await controller.Rotate(fileId, request);

        var file = await db.Files.FindAsync(fileId);

        Assert.Equal(2, file!.FileEncryptionVersion);
        Assert.Equal(2, db.FileAccesses.Count());
    }

    [Fact]
    public async Task Old_Version_Access_Fails()
    {
        await using var db = GetDb();

        var userId = Guid.NewGuid();
        var fileId = Guid.NewGuid();

        db.Files.Add(new FileRecord
        {
            Id = fileId,
            UserId = userId,
            EncryptedFileName = "file.txt",
            ManifestBlobPath = "manifest/path",
            UploadedAt = DateTime.UtcNow,
            ContentType = "application/octet-stream",
            CryptoVersion = "v1-simple",
            FileEncryptionVersion = 2
        });

        db.FileAccesses.Add(new FileAccess
        {
            FileRecordId = fileId,
            UserId = userId,
            Permissions = "owner",
            WrappedDek = "old-key",
            KeyVersion = 1,
            FileEncryptionVersion = 1, // OLD VERSION
            CreatedAt = DateTime.UtcNow,
            RevokedAt = null
        });

        await db.SaveChangesAsync();

        var controller = new FilesController(db, null!, null!)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = CreateUser(userId)
                }
            }
        };

        var result = await controller.GetFileKey(fileId);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task GetFileKey_Returns_New_Version()
    {
        await using var db = GetDb();

        var userId = Guid.NewGuid();
        var fileId = Guid.NewGuid();

        db.Files.Add(new FileRecord
        {
            Id = fileId,
            UserId = userId,
            EncryptedFileName = "file.txt",
            ManifestBlobPath = "manifest/path",
            UploadedAt = DateTime.UtcNow,
            ContentType = "application/octet-stream",
            CryptoVersion = "v1-simple",
            FileEncryptionVersion = 2
        });

        db.FileAccesses.Add(new FileAccess
        {
            FileRecordId = fileId,
            UserId = userId,
            Permissions = "owner",
            WrappedDek = "new-key",
            KeyVersion = 2,
            FileEncryptionVersion = 2,
            CreatedAt = DateTime.UtcNow,
            RevokedAt = null
        });

        await db.SaveChangesAsync();

        var controller = new FilesController(db, null!, null!)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = CreateUser(userId)
                }
            }
        };

        var result = await controller.GetFileKey(fileId);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);
    }

    [Fact]
    public async Task Removed_User_Loses_Access()
    {
        await using var db = GetDb();

        var ownerId = Guid.NewGuid();
        var removedUser = Guid.NewGuid();
        var fileId = Guid.NewGuid();

        db.Files.Add(new FileRecord
        {
            Id = fileId,
            UserId = ownerId,
            EncryptedFileName = "file.txt",
            ManifestBlobPath = "manifest/path",
            UploadedAt = DateTime.UtcNow,
            ContentType = "application/octet-stream",
            CryptoVersion = "v1-simple",
            FileEncryptionVersion = 2
        });

        db.FileAccesses.Add(new FileAccess
        {
            FileRecordId = fileId,
            UserId = removedUser,
            Permissions = "viewer",
            WrappedDek = "old-key",
            KeyVersion = 1,
            FileEncryptionVersion = 1,
            CreatedAt = DateTime.UtcNow,
            RevokedAt = DateTime.UtcNow
        });

        await db.SaveChangesAsync();

        var controller = new FilesController(db, null!, null!)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = CreateUser(removedUser)
                }
            }
        };

        var result = await controller.GetFileKey(fileId);

        Assert.IsType<ForbidResult>(result);
    }
}