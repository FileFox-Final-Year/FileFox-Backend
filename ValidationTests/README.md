# API Functionality Analysis & Validation Report

This report summarizes the testing performed on the FileFox API to validate its core functionalities.

## Summary of Results

| Feature | Status | Verification Method |
| :--- | :--- | :--- |
| **Authentication** | ✅ PASS | `Authentication_RequiredForFiles` test verifies 401 on unauthorized access. |
| **Authorization** | ✅ PASS | `Authorization_CannotAccessOthersFiles` test ensures User A cannot see User B's files. |
| **Encryption** | ✅ PASS | `EncryptionAndMetadata_Preserved` test verifies ciphertext is stored and returned as-is. |
| **Metadata Encryption** | ✅ PASS | `EncryptionAndMetadata_Preserved` test verifies `EncryptedMetadata` persistence. |
| **MFA Recovery** | ✅ PASS | `MfaRecovery_Works` test performs full MFA setup and login using a recovery code. |
| **File Recovery** | ✅ PASS | `EncryptionAndMetadata_Preserved` test verifies `RecoveryWrappedKey` persistence. |
| **Rate Limiting** | ✅ PASS | `RateLimiting_Auth_Triggers` test verifies 429 after 11 failed login attempts. |
| **Security Headers** | ✅ PASS | `SecurityHeaders_Present` test verifies presence of HSTS, CSP, XFO, etc. |
| **Auditing** | ✅ PASS | `Auditing_LogsLogin` test verifies creation of registration and login audit logs. |

## Detailed Analysis

### 1. Authentication & Authorization
The system correctly enforces JWT Bearer token requirements for all file-related operations. User isolation is maintained at the database query level, returning 404/NotFound when a user attempts to access a file ID that exists but is not owned by them.

### 2. Client-Side Encryption Support
The API serves as a "blind" storage provider. Tests confirmed that `EncryptedFileName`, `EncryptedMetadata`, and `RecoveryWrappedKey` are treated as opaque strings/blobs, ensuring the server cannot decrypt file contents or metadata without the client's keys.

### 3. Multi-Factor Authentication (MFA)
The MFA flow was validated through its lifecycle:
- Setup generates a Base32 secret and 10 secure recovery codes.
- Verification correctly enables MFA for the user.
- Login requires a two-step process when MFA is enabled.
- Recovery codes (single-use) successfully bypass the TOTP requirement.

### 4. Security Hardening
- **Rate Limiting**: Effectively throttles aggressive login attempts to 10 per minute, returning HTTP 429.
- **Security Headers**: All responses include standard hardening headers:
  - `Content-Security-Policy`: Restricts resource loading.
  - `X-Frame-Options: DENY`: Prevents clickjacking.
  - `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing.
- **Auditing**: Critical security events (Registration, Login) are successfully persisted to the `AuditLogs` table with associated timestamps and user IDs.

---

## How to Run Validation Tests

Follow these steps to execute the validation suite and verify specific functionalities.

### Prerequisites
- .NET 8.0 SDK or higher.
- A terminal in the repository root.

### Running All Validation Tests
To run the entire suite of 10 integration tests:
```bash
dotnet test ValidationTests/ValidationTests.csproj
```

### Running Specific Validations
You can run individual tests to focus on specific functionality using the `--filter` flag:

| Functionality | Test Name | Command |
| :--- | :--- | :--- |
| **Authentication** | `Authentication_RequiredForFiles` | `dotnet test ValidationTests/ValidationTests.csproj --filter Authentication_RequiredForFiles` |
| **Authorization** | `Authorization_CannotAccessOthersFiles` | `dotnet test ValidationTests/ValidationTests.csproj --filter Authorization_CannotAccessOthersFiles` |
| **Encryption/Recovery** | `EncryptionAndMetadata_Preserved` | `dotnet test ValidationTests/ValidationTests.csproj --filter EncryptionAndMetadata_Preserved` |
| **MFA / Recovery Codes** | `MfaRecovery_Works` | `dotnet test ValidationTests/ValidationTests.csproj --filter MfaRecovery_Works` |
| **Rate Limiting** | `RateLimiting_Auth_Triggers` | `dotnet test ValidationTests/ValidationTests.csproj --filter RateLimiting_Auth_Triggers` |
| **Security Headers** | `SecurityHeaders_Present` | `dotnet test ValidationTests/ValidationTests.csproj --filter SecurityHeaders_Present` |
| **Auditing** | `Auditing_LogsLogin` | `dotnet test ValidationTests/ValidationTests.csproj --filter Auditing_LogsLogin` |
| **File Lifecycle** | `FileLifecycle_Full_Works` | `dotnet test ValidationTests/ValidationTests.csproj --filter FileLifecycle_Full_Works` |
| **Key Management** | `KeyManagement_Works` | `dotnet test ValidationTests/ValidationTests.csproj --filter KeyManagement_Works` |
| **Refresh Tokens** | `RefreshToken_Works` | `dotnet test ValidationTests/ValidationTests.csproj --filter RefreshToken_Works` |

### Environment Notes
These tests use an **In-Memory Database** and a mocked configuration. They are designed to run in isolation without requiring a live SQL Server instance, making them suitable for CI/CD pipelines and local rapid validation.
