# FileFox API Documentation

This directory contains the controllers that expose the FileFox Web API. This document provides a granular explanation of each endpoint, how they interact, and how to use them in a client application (like a website).

## Table of Contents
1. [Authentication Flow](#1-authentication-flow)
2. [Key Management Flow](#2-key-management-flow)
3. [File Upload Flow (Chunked)](#3-file-upload-flow-chunked)
4. [File Download Flow](#4-file-download-flow)
5. [Controller Reference](#controller-reference)
   - [AuthController](#authcontroller)
   - [FilesController](#filescontroller)
   - [KeyController](#keycontroller)
   - [TestController](#testcontroller)

---

## 1. Authentication Flow

FileFox uses JWT (JSON Web Tokens) for authentication, supporting both standard login and Multi-Factor Authentication (MFA).

### Standard Login
1. **Register**: `POST /auth/register` with username, email, and password.
2. **Login**: `POST /auth/login` with email and password.
3. **Handle Response**:
   - If MFA is NOT enabled: You receive an `AccessToken` and `RefreshToken`.
   - If MFA IS enabled: You receive an `mfaRequired: true` flag and a temporary `mfaToken`.

### MFA Setup (While Logged In)
1. **Initiate**: `POST /auth/mfa/setup`. It returns a `base32Secret` and an `otpAuthUri`. Display the QR code to the user using the URI.
2. **Verify**: `POST /auth/mfa/verify` with the 6-digit code from the user's authenticator app. This enables MFA for the account.

### MFA Login
1. **Login**: `POST /auth/login` returns `mfaToken`.
2. **Validate**: `POST /auth/login/mfa` with the `mfaToken` and the 6-digit `code`. Returns `AccessToken` and `RefreshToken`.

### Token Rotation
- Use `POST /auth/refresh` with your `RefreshToken` to get a new pair of tokens. This should be done before the access token expires.

---

## 2. Key Management Flow

FileFox is designed for client-side encryption. The server stores your keys, but the private key is encrypted with a key derived from your password (or another client-side secret).

1. **Register Key**: After registration or when changing passwords, use `POST /keys/register` to store your public key and encrypted private key.
2. **Retrieve Key**: Use `GET /keys/me` to get your keys when logging in from a new device.
3. **Sharing**: Use `GET /keys/public/{userId}` to get another user's public key for sharing encrypted files.

---

## 3. File Upload Flow (Chunked)

For large files or resilient uploads, use the chunked upload flow.

1. **Initialize**: `POST /files/init`.
   - Send `EncryptedFileName`, `TotalSize`, `ChunkSize`, and a `WrappedFileKey` (the file's AES key encrypted with your public key).
   - You can also send `EncryptedMetadata` and `RecoveryWrappedKey`.
   - Also send an `EncryptedManifestHeader` which contains encryption metadata (IVs, nonces, etc.).
   - Receive a `fileId`.
2. **Upload Chunks**: Loop through your file chunks and call `PUT /files/{fileId}/chunks/{index}`.
   - Send the raw encrypted bytes for that chunk in the request body.
3. **Complete**: `POST /files/{fileId}/complete` to notify the server that all chunks are uploaded.

---

## 4. File Download Flow

### Direct Download (Concatenated)
- `GET /files/{id}/download`: Streams all chunks back as a single continuous file. The browser will handle this as a standard download.

### Client-Side Decryption Flow
1. **Get Metadata**: `GET /files/{id}`. This gives you the `WrappedKeys` and `FileName` (encrypted).
2. **Decrypt Metadata**: Decrypt the `WrappedFileKey` using your private key.
3. **Get Manifest**: `GET /files/{id}/manifest`. Contains the metadata needed to decrypt individual chunks.
4. **Get Chunks**: `GET /files/{id}/chunks/{index}` for each chunk.
5. **Decrypt & Assemble**: Decrypt each chunk in the browser and combine them into a Blob.

---

## Controller Reference

### AuthController
Base Route: `/auth`

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/register` | POST | Anonymous | Registers a new user. |
| `/login` | POST | Anonymous | Step 1: Returns JWT or MFA requirement. |
| `/login/mfa` | POST | Anonymous | Step 2: Validates MFA code and returns JWT. |
| `/login/recovery` | POST | Anonymous | Step 2 Alt: Validates MFA Recovery Code and returns JWT. |
| `/refresh` | POST | Anonymous | Rotates Refresh and Access tokens. |
| `/mfa/setup` | POST | Authorized | Generates a new MFA secret. |
| `/mfa/verify` | POST | Authorized | Verifies and enables MFA. |

### FilesController
Base Route: `/files`

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/` | GET | Authorized | Lists all files owned by the user. |
| `/upload` | POST | Authorized | Direct multipart/form-data upload. |
| `/init` | POST | Authorized | Initializes a chunked upload. |
| `/{id}/chunks/{i}` | PUT | Authorized | Uploads chunk `i` for file `id`. |
| `/{id}/complete` | POST | Authorized | Completes the chunked upload. |
| `/{id}` | GET | Authorized | Gets metadata for file `id`. |
| `/{id}/manifest` | GET | Authorized | Gets the encrypted manifest header. |
| `/{id}/chunks/{i}` | GET | Authorized | Downloads chunk `i` for file `id`. |
| `/{id}/download` | GET | Authorized | Downloads the full file (streaming). |

### KeyController
Base Route: `/keys`

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/register` | POST | Authorized | Registers a new User Key Pair. |
| `/me` | GET | Authorized | Gets the current user's key pair. |
| `/public/{uid}` | GET | Anonymous | Gets the public key for user `uid`. |

### TestController
Base Route: `/Test`

- `GET /test-error`: Used to verify global error handling. Throws a 500 exception.

---

## Website Implementation Example (Pseudo-code)

### Uploading a File
```javascript
// 1. Generate a random AES key for the file
const fileKey = generateAesKey();

// 2. Encrypt the file key with the User's Public Key
const wrappedKey = encryptWithPublicKey(userPublicKey, fileKey);

// 3. Initialize upload
const { fileId } = await api.post('/files/init', {
  encryptedFileName: encrypt(fileKey, "my-photo.jpg"),
  totalSize: file.size,
  chunkSize: 1024 * 1024, // 1MB
  wrappedFileKey: wrappedKey,
  // ... other metadata
});

// 4. Upload chunks
for (let i = 0; i < chunks.length; i++) {
  const encryptedChunk = encryptChunk(fileKey, chunks[i]);
  await api.put(`/files/${fileId}/chunks/${i}`, encryptedChunk);
}

// 5. Complete
await api.post(`/files/${fileId}/complete`);
```
