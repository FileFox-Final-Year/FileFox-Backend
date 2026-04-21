namespace FileFox_Backend.Core.Interfaces;

public interface IFileAuthorizationService
{
    Task<bool> IsOwner(Guid fileId, Guid userId);
    Task<bool> HasAccess(Guid fileId, Guid userId);
    Task<bool> CanShare(Guid fileId, Guid userId);
}