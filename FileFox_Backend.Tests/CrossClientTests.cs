using Xunit;
using System;
using System.Linq;
using FileFox_Backend.Infrastructure.Services;

namespace FileFox_Backend.Tests;

public class CrossClientTests
{
    private readonly ManifestService _manifestService;

    public CrossClientTests()
    {
        _manifestService = new ManifestService();
    }

    [Fact]
    public void ClientA_Computes_ManifestHash_ClientB_Verifies()
    {
        // --- CLIENT A: Compute manifest hash ---
        var clientAChunkHashes = new[]
        {
            "hash_chunk_0_from_clientA",
            "hash_chunk_1_from_clientA",
            "hash_chunk_2_from_clientA"
        };

        var manifestHashA = _manifestService.ComputeManifestHash(clientAChunkHashes);

        // --- CLIENT B: Receives same chunk hashes, verifies manifest hash ---
        var clientBChunkHashes = clientAChunkHashes; // Same chunks received over network
        var isValidB = _manifestService.VerifyManifestHash(manifestHashA, clientBChunkHashes);

        Assert.True(isValidB, "Client B should verify the manifest hash computed by Client A");
    }

    [Fact]
    public void ClientA_Chunks_ClientB_Detects_Dropped()
    {
        // --- CLIENT A: Upload 3 chunks (0, 1, 2) ---
        var clientAChunkIndices = new[] { 0, 1, 2 };
        var totalChunks = 3;

        var isValidA = _manifestService.VerifyChunkSequence(totalChunks, clientAChunkIndices);
        Assert.True(isValidA, "All chunks present");

        // --- CLIENT B: Detects missing chunk (only has 0, 2 - missing 1) ---
        var droppedChunkIndices = new[] { 0, 2 };
        var isValidB = _manifestService.VerifyChunkSequence(totalChunks, droppedChunkIndices);
        Assert.False(isValidB, "Client B should detect dropped chunk");
    }

    [Fact]
    public void ClientA_Chunks_ClientB_Detects_Extra()
    {
        // --- CLIENT A: Upload 2 chunks (0, 1) ---
        var totalChunks = 2;

        // --- CLIENT B: Detects extra chunk (0, 1, 2 when only 2 expected) ---
        var extraChunkIndices = new[] { 0, 1, 2 };
        var isValidB = _manifestService.VerifyChunkSequence(totalChunks, extraChunkIndices);
        Assert.False(isValidB, "Client B should detect extra chunk");
    }

    [Fact]
    public void ManifestHash_Detects_HashTampering()
    {
        // --- CLIENT A: Compute manifest hash ---
        var chunkHashes = new[] { "hash_a", "hash_b", "hash_c" };
        var originalHash = _manifestService.ComputeManifestHash(chunkHashes);

        // --- ATTACKER: Modify chunk order in manifest ---
        var tamperedChunkHashes = new[] { "hash_b", "hash_a", "hash_c" }; // Reordered
        var tamperedHash = _manifestService.ComputeManifestHash(tamperedChunkHashes);

        // --- CLIENT B: Verify tampering is detected ---
        var isValid = _manifestService.VerifyManifestHash(originalHash, tamperedChunkHashes);
        Assert.False(isValid, "Reordering should change manifest hash");
    }

    [Fact]
    public void ClientA_ChunkHashes_ClientB_VerifiesChunk()
    {
        // --- CLIENT A: Encrypt chunk data ---
        var plainChunkData = System.Text.Encoding.UTF8.GetBytes("This is encrypted chunk data from Client A");
        var chunkHash = _manifestService.ComputeChunkHash(plainChunkData);

        // --- CLIENT B: Receives same chunk data, verifies hash ---
        var isValid = _manifestService.VerifyChunkHash(plainChunkData, chunkHash);
        Assert.True(isValid, "Client B should verify chunk hash matches");
    }

    [Fact]
    public void ClientB_Detects_CorruptedChunk()
    {
        // --- CLIENT A: Compute hash of original chunk ---
        var originalChunkData = System.Text.Encoding.UTF8.GetBytes("Original chunk data");
        var originalHash = _manifestService.ComputeChunkHash(originalChunkData);

        // --- ATTACKER: Corrupt the chunk data ---
        var corruptedChunkData = System.Text.Encoding.UTF8.GetBytes("Corrupted chunk data");

        // --- CLIENT B: Verify corruption is detected ---
        var isValid = _manifestService.VerifyChunkHash(corruptedChunkData, originalHash);
        Assert.False(isValid, "Client B should detect corrupted chunk");
    }

    [Fact]
    public void IntegrityReport_ContainsAuditableInfo()
    {
        var fileId = Guid.NewGuid();
        var totalChunks = 5;
        var manifestHash = "test_hash_123";
        var isValid = true;

        var report = _manifestService.GenerateIntegrityReport(fileId, totalChunks, manifestHash, isValid);

        // Verify report structure (must not leak secrets like hashes)
        Assert.NotNull(report);
        var integrityReport = (ManifestService.IntegrityReport)report;
        Assert.Equal(fileId, integrityReport.FileId);
        Assert.Equal(totalChunks, integrityReport.TotalChunks);
        Assert.Equal(isValid, integrityReport.ManifestHashValid);
        Assert.Equal("INTEGRITY_VERIFIED", integrityReport.Status);
    }

    [Fact]
    public void MultiClient_ScenarioComplete()
    {
        // Simulates a complete multi-client scenario:
        // 1. Client A prepares 3 chunks and computes manifest
        // 2. Client B receives chunks and verifies integrity
        // 3. Both clients agree on manifest validity

        // --- CLIENT A SIDE ---
        var clientAChunks = new[]
        {
            "chunk_data_1_encrypted",
            "chunk_data_2_encrypted",
            "chunk_data_3_encrypted"
        };
        var clientAChunkHashes = clientAChunks.Select(c => ComputeChunkHash(System.Text.Encoding.UTF8.GetBytes(c))).ToList();
        var manifestHashA = _manifestService.ComputeManifestHash(clientAChunkHashes);

        // --- NETWORK TRANSMISSION ---
        // Manifest and chunks sent to Client B

        // --- CLIENT B SIDE ---
        var receivedChunkHashes = clientAChunkHashes;
        var receivedChunkIndices = new[] { 0, 1, 2 };

        // Client B verifies:
        var hashValid = _manifestService.VerifyManifestHash(manifestHashA, receivedChunkHashes);
        var sequenceValid = _manifestService.VerifyChunkSequence(3, receivedChunkIndices);

        Assert.True(hashValid, "Hash verification should pass");
        Assert.True(sequenceValid, "Sequence verification should pass");
    }

    // Helper method to compute chunk hash (simulates SHA256)
    private string ComputeChunkHash(byte[] data)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(data);
        return Convert.ToBase64String(hash);
    }
}
