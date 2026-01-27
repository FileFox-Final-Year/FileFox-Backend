using Microsoft.Extensions.Configuration;

namespace FileFox_Backend.Services;

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