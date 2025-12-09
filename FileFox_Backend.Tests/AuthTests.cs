using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FileFox_Backend.Data;
using FileFox_Backend.Models;
using FileFox_Backend.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;


namespace FileFox_Backend.Tests;

public class AuthTests
{
    private ApplicationDbContext GetInMemoryDb()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new ApplicationDbContext(options);
    }

    private EFCoreUserStore GetUserStore(ApplicationDbContext db) => new EFCoreUserStore(db);
    private RefreshTokenService GetRefreshTokenService(ApplicationDbContext db) => new RefreshTokenService(db);

    [Fact]
    public async Task Register_Login_Refresh_Success()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);
        var tokenService = GetRefreshTokenService(db);

        // Register
        var (created, user, error) =
            await userStore.RegisterAsync("testuser", "test@example.com", "password123");

        Assert.True(created);
        Assert.NotNull(user);
        Assert.Null(error);

        // Login
        var loggedIn = await userStore.ValidateCredentialsAsync("test@example.com", "password123");
        Assert.NotNull(loggedIn);
        Assert.Equal(user!.Id, loggedIn!.Id);

        // Generate Refresh Token
        var refreshToken = await tokenService.GenerateTokenAsync(user.Id);
        Assert.NotNull(refreshToken);
        Assert.True(refreshToken.IsActive);

        // Validate Refresh Token
        var validated = await tokenService.ValidateTokenAsync(refreshToken.Token);
        Assert.NotNull(validated);
        Assert.Equal(refreshToken.Token, validated!.Token);
    }

    [Fact]
    public async Task Invalid_Login_Fails()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);

        // Register
        await userStore.RegisterAsync("testuser", "test@example.com", "password123");

        // Invalid password
        var invalid = await userStore.ValidateCredentialsAsync("test@example.com", "wrongpassword");
        Assert.Null(invalid);

        // Invalid username
        var invalidUser = await userStore.ValidateCredentialsAsync("wrong@example.com", "password123");
        Assert.Null(invalidUser);
    }

    [Fact]
    public async Task Expired_RefreshToken_Fails()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);
        var tokenService = GetRefreshTokenService(db);

        // Register & Login
        var (_, user, _) =
            await userStore.RegisterAsync("testuser", "test@example.com", "password123");

        Assert.NotNull(user);

        // Create token that expires immediately
        var refreshToken = await tokenService.GenerateTokenAsync(user!.Id, daysValid: -1);

        // Validation should fail
        var validated = await tokenService.ValidateTokenAsync(refreshToken.Token);
        Assert.Null(validated);
    }

    [Fact]
    public async Task Reused_RefreshToken_Fails_After_Revoke()
    {
        using var db = GetInMemoryDb();
        var userStore = GetUserStore(db);
        var tokenService = GetRefreshTokenService(db);

        var (_, user, _) =
            await userStore.RegisterAsync("testuser", "test@example.com", "password123");

        Assert.NotNull(user);

        var refreshToken = await tokenService.GenerateTokenAsync(user!.Id);

        // Validate first time succeeds
        var validated1 = await tokenService.ValidateTokenAsync(refreshToken.Token);
        Assert.NotNull(validated1);

        // Revoke token
        await tokenService.RevokeTokenAsync(refreshToken.Token);

        // Second validation fails
        var validated2 = await tokenService.ValidateTokenAsync(refreshToken.Token);
        Assert.Null(validated2);
    }
}
