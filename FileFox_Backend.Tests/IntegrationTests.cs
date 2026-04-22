using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace FileFox_Backend.Tests;

public class LoginResponse
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
}

public class AuthIntegrationTests 
    : IClassFixture<TestWebApplicationFactory>
{
    private readonly HttpClient _client;

    public AuthIntegrationTests(TestWebApplicationFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Register_Login_Flow_Returns_JWT()
    {
        var email = $"user_{Guid.NewGuid()}@test.com";

        var register = new
        {
            username = "integrationUser",
            email = email,
            password = "Password123!"
        };

        var registerResponse =
            await _client.PostAsJsonAsync("/auth/register", register);

        registerResponse.StatusCode.Should().Be(HttpStatusCode.Created);

        var login = new
        {
            email = email,
            password = "Password123!"
        };

        var loginResponse =
            await _client.PostAsJsonAsync("/auth/login", login);

        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var body =
            await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();

        body!.AccessToken.Should().NotBeNullOrEmpty();
    }
}