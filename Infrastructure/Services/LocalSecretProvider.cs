using Microsoft.Extensions.Configuration;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Infrastructure.Services;

public class LocalSecretProvider : ISecretProvider
{
    private readonly IConfiguration _config;

    public LocalSecretProvider(IConfiguration config)
    {
        _config = config;
    }

    public string GetSecret(string key)
    {
        var value = _config[key];
        
        if (string.IsNullOrWhiteSpace(value))
            throw new Exception($"Missing secret: {key}");

        return value;
    }
}