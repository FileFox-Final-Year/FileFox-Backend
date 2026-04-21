using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using FileFox_Backend.Controllers;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using FileFox_Backend.Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace FileFox_Backend.Tests.Phase5
{
    public class ShareControllerTests
    {
        private ApplicationDbContext GetInMemoryDb()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;
            return new ApplicationDbContext(options);
        }

        private ClaimsPrincipal CreateUser(Guid userId)
        {
            return new ClaimsPrincipal(new ClaimsIdentity(new Claim[]
            {
                new Claim("sub", userId.ToString())
            }, "test"));
        }

        [Fact]
        public async Task Owner_Can_Share_And_Recipient_Can_Access()
        {
            await using var db = GetInMemoryDb();

            var ownerId = Guid.NewGuid();
            var recipientId = Guid.NewGuid();
            var fileId = Guid.NewGuid();

            var owner = new User 
            { 
                Id = ownerId, 
                UserName = "owner",
                Email = "owner@test.com",
                PasswordHash = "hash"
            };
            var recipient = new User 
            { 
                Id = recipientId, 
                UserName = "recipient",
                Email = "recipient@test.com",
                PasswordHash = "hash"
            };
            db.Users.AddRange(owner, recipient);

            var file = new FileRecord 
            { 
                Id = fileId, 
                UserId = ownerId, 
                EncryptedFileName = "file.enc",
                TotalSize = 1024,
                ManifestBlobPath = "test"
            };
            db.Files.Add(file);

            db.FileAccesses.Add(new FileFox_Backend.Core.Models.FileAccess
            {
                FileRecordId = fileId,
                UserId = ownerId,
                Permissions = "owner",
                WrappedDek = "owner-key",
                CreatedAt = DateTime.UtcNow
            });

            await db.SaveChangesAsync();

            var controller = new ShareController(db, new FileAuthorizationService(db), new AuditService(db))
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext { User = CreateUser(ownerId) }
                }
            };

            var shareRequest = new ShareController.ShareRequest
            {
                RecipientUserId = recipientId,
                WrappedDek = "wrapped-key",
                Permissions = "read",
                KeyVersion = 1
            };

            var result = await controller.ShareFile(fileId, shareRequest);
            Assert.NotNull(db.FileAccesses.FirstOrDefault(f =>
                f.FileRecordId == fileId && f.UserId == recipientId && f.RevokedAt == null));
        }

        [Fact]
        public async Task Recipient_Cannot_Access_After_Revoke()
        {
            await using var db = GetInMemoryDb();

            var ownerId = Guid.NewGuid();
            var recipientId = Guid.NewGuid();
            var fileId = Guid.NewGuid();

            var owner = new User 
            { 
                Id = ownerId, 
                UserName = "owner",
                Email = "owner@test.com",
                PasswordHash = "hash"
            };
            var recipient = new User 
            { 
                Id = recipientId, 
                UserName = "recipient",
                Email = "recipient@test.com",
                PasswordHash = "hash"
            };
            db.Users.AddRange(owner, recipient);

            var file = new FileRecord 
            { 
                Id = fileId, 
                UserId = ownerId, 
                EncryptedFileName = "file.enc",
                TotalSize = 1024,
                ManifestBlobPath = "test"
            };
            db.Files.Add(file);

            db.FileAccesses.AddRange(
                new FileFox_Backend.Core.Models.FileAccess 
                { 
                    FileRecordId = fileId, 
                    UserId = ownerId, 
                    Permissions = "owner",
                    WrappedDek = "owner-key",
                    CreatedAt = DateTime.UtcNow 
                },
                new FileFox_Backend.Core.Models.FileAccess 
                { 
                    FileRecordId = fileId, 
                    UserId = recipientId, 
                    Permissions = "read", 
                    WrappedDek = "key123",
                    CreatedAt = DateTime.UtcNow
                }
            );

            await db.SaveChangesAsync();

            var shareController = new ShareController(db, new FileAuthorizationService(db), new AuditService(db))
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext { User = CreateUser(ownerId) }
                }
            };

            await shareController.RevokeShare(fileId, recipientId);

            var access = db.FileAccesses.First(f => f.FileRecordId == fileId && f.UserId == recipientId);
            Assert.NotNull(access.RevokedAt);
        }

        [Fact]
        public async Task Owner_Can_List_Shares()
        {
            await using var db = GetInMemoryDb();

            var ownerId = Guid.NewGuid();
            var recipientId = Guid.NewGuid();
            var fileId = Guid.NewGuid();

            var owner = new User 
            { 
                Id = ownerId,
                UserName = "owner",
                Email = "owner@test.com",
                PasswordHash = "hash"
            };
            var recipient = new User 
            { 
                Id = recipientId,
                UserName = "recipient",
                Email = "recipient@test.com",
                PasswordHash = "hash"
            };
            db.Users.AddRange(owner, recipient);

            var file = new FileRecord 
            { 
                Id = fileId, 
                UserId = ownerId,
                EncryptedFileName = "file.enc",
                TotalSize = 1024,
                ManifestBlobPath = "test"
            };
            db.Files.Add(file);

            db.FileAccesses.AddRange(
                new FileFox_Backend.Core.Models.FileAccess 
                { 
                    FileRecordId = fileId, 
                    UserId = ownerId, 
                    Permissions = "owner",
                    WrappedDek = "owner-key",
                    CreatedAt = DateTime.UtcNow 
                },
                new FileFox_Backend.Core.Models.FileAccess 
                { 
                    FileRecordId = fileId, 
                    UserId = recipientId, 
                    Permissions = "read",
                    WrappedDek = "shared-key",
                    CreatedAt = DateTime.UtcNow
                }
            );

            await db.SaveChangesAsync();

            var controller = new ShareController(db, new FileAuthorizationService(db), new AuditService(db))
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext { User = CreateUser(ownerId) }
                }
            };

            var result = await controller.GetShares(fileId);
            var okResult = Assert.IsType<OkObjectResult>(result);
            var shares = Assert.IsAssignableFrom<IEnumerable<object>>(okResult.Value);

            Assert.NotNull(shares);
        }
    }
}
