using FileFox_Backend.Core.Models;
namespace FileFox_Backend.Core.Interfaces;

public interface ISecretProvider
{
    string GetSecret(string key);
}