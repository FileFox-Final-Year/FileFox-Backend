using Microsoft.AspNetCore.Authorization;

using FileFox_Backend.Core.Interfaces;
namespace FileFox_Backend.Infrastructure.Authorization
{
    public class FileOwnerRequirement : IAuthorizationRequirement
    {
    }
}