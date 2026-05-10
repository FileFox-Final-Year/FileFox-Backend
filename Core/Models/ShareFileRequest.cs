using System.ComponentModel.DataAnnotations;

namespace FileFox_Backend.Core.Models;

public class ShareFileRequest
{
    [Required]
    [EmailAddress]
    public string RecipientEmail { get; set; } = null!;

    [Required]
    public string WrappedFileKey { get; set; } = null!;
}
