namespace FileFox_Backend.Services;

public interface ISecretProvider
{
    string GetSecret(string key);
}