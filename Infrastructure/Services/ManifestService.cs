using System.Security.Cryptography;
using System.Text;

public class ManifestService
{
    public string ComputeManifestHash(IEnumerable<string> chunkHashes)
    {
        var combined = string.Join("", chunkHashes);

        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(combined));

        return Convert.ToBase64String(hash);
    }

    public bool VerifyManifestHash(string expectedHash, IEnumerable<string> chunkHashes)
    {
        var computed = ComputeManifestHash(chunkHashes);
        return computed == expectedHash;
    }

    public bool VerifyChunkSequence(int totalChunks, IEnumerable<int> availableChunkIndices)
    {
        var indices = availableChunkIndices.OrderBy(i => i).ToList();

        // Check for correct count
        if (indices.Count != totalChunks)
            return false;

        // Check for sequential order (0, 1, 2, ...)
        for (int i = 0; i < indices.Count; i++)
        {
            if (indices[i] != i)
                return false;
        }

        return true;
    }

    public string ComputeChunkHash(byte[] chunkData)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(chunkData);
        return Convert.ToBase64String(hash);
    }

    public bool VerifyChunkHash(byte[] chunkData, string expectedHash)
    {
        var computed = ComputeChunkHash(chunkData);
        return computed == expectedHash;
    }

    public IntegrityReport GenerateIntegrityReport(Guid fileId, int totalChunks, string manifestHash, bool isValid)
    {
        return new IntegrityReport
        {
            FileId = fileId,
            Timestamp = DateTimeOffset.UtcNow,
            TotalChunks = totalChunks,
            ManifestHashValid = isValid,
            Status = isValid ? "INTEGRITY_VERIFIED" : "INTEGRITY_VIOLATION_DETECTED"
        };
    }

    public class IntegrityReport
    {
        public Guid FileId { get; set; }
        public DateTimeOffset Timestamp { get; set; }
        public int TotalChunks { get; set; }
        public bool ManifestHashValid { get; set; }
        public string Status { get; set; } = null!;
    }
}
