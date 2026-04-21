using System;
using System.Linq;
using System.Threading.Tasks;
using FileFox_Backend.Infrastructure.Services;
using FileFox_Backend.Core.Models;
using FileFox_Backend.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Xunit;

public class RecoveryCodeServiceTests
{
    private ApplicationDbContext CreateDb()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new ApplicationDbContext(options);
    }

    [Fact]
    public async Task GenerateRecoveryCodes_ShouldReturnCorrectCount()
    {
        var db = CreateDb();
        var service = new RecoveryCodeService(db);

        var (plaintext, hashes) = await service.GenerateRecoveryCodesAsync(10);

        Assert.Equal(10, plaintext.Count);
        Assert.Equal(10, hashes.Count);
    }

    [Fact]
    public async Task ValidateRecoveryCode_ShouldMarkCodeUsed()
    {
        var db = CreateDb();
        var service = new RecoveryCodeService(db);

        var userId = Guid.NewGuid();
        var (plaintext, hashes) = await service.GenerateRecoveryCodesAsync(1);

        db.RecoveryCodes.Add(new RecoveryCode
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            CodeHash = hashes[0],
            KeyVersion = 1,
            CreatedAt = DateTimeOffset.UtcNow
        });

        await db.SaveChangesAsync();

        var valid = await service.ValidateAndUseRecoveryCodeAsync(
            userId,
            plaintext[0],
            1
        );

        Assert.True(valid);

        var code = db.RecoveryCodes.First();
        Assert.NotNull(code.UsedAt);
    }

    [Fact]
    public async Task ValidateRecoveryCode_ShouldFailForWrongCode()
    {
        var db = CreateDb();
        var service = new RecoveryCodeService(db);

        var userId = Guid.NewGuid();

        db.RecoveryCodes.Add(new RecoveryCode
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            CodeHash = service.HashRecoveryCode("AAAA-BBBB-CCCC"),
            KeyVersion = 1
        });

        await db.SaveChangesAsync();

        var valid = await service.ValidateAndUseRecoveryCodeAsync(
            userId,
            "WRONG-CODE-0000",
            1
        );

        Assert.False(valid);
    }
}