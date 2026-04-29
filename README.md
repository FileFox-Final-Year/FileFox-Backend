# FileFox-Backend

FileFox-Backend is a secure, client-side encrypted file storage API. All files are encrypted before they reach the server, ensuring maximum privacy.

## How to Test Using Swagger UI

Follow these steps to test the API flow from registration to file retrieval.

### 1. Register a New User
1. Open the Swagger UI (usually at `https://localhost:5026/swagger/index.html` in development).
2. Locate the **`POST /auth/register`** endpoint.
3. Click **"Try it out"**.
4. Enter a JSON body with `userName`, `email`, and `password`.
5. Click **"Execute"**.
6. On success, you will receive a `201 Created` response containing your initial JWT token.

### 2. Login
If you already have an account:
1. Locate the **`POST /auth/login`** endpoint.
2. Click **"Try it out"**.
3. Enter your `email` and `password`.
4. Click **"Execute"**.
5. Copy the `accessToken` from the response body.

### 3. Authorize Swagger UI
1. Scroll to the top of the Swagger page and click the **"Authorize"** button (padlock icon).
2. In the **"Value"** text box, paste the `accessToken` you copied.
3. Click **"Authorize"** and then **"Close"**.
   - *Note: You do NOT need to type "Bearer " anymore; the UI handles it for you.*

### 4. Upload a File

#### Option A: Direct Upload (Simple)
1. Locate **`POST /files/upload`**.
2. Click **"Try it out"**.
3. Use the file picker to select a file.
4. Click **"Execute"**.
5. Copy the returned `fileId`.

#### Option B: Chunked Upload (Encrypted Flow)
1. **Initialize**: Call **`POST /files/init`** with the encrypted manifest header and filename. Copy the returned `fileId`.
2. **Upload Chunks**: Call **`PUT /files/{id}/chunks/{index}`** for each chunk.
   - Set `{id}` to your `fileId`.
   - Set `{index}` starting from 0.
   - Provide the binary data in the request body.
3. **Complete**: Call **`POST /files/{id}/complete`** to finalize the upload.

### 5. Retrieve a File
1. **List Files**: Call **`GET /files`** to see all your uploaded files and their IDs.
2. **Get Metadata**: Call **`GET /files/{id}`** to get details about a specific file.
3. **Download Manifest**: Call **`GET /files/{id}/manifest`** to retrieve the encrypted manifest.
4. **Download Chunks**: Call **`GET /files/{id}/chunks/{index}`** to retrieve the encrypted data chunks.

## AWS RDS SQL Server Setup

This project uses Amazon RDS for SQL Server for persistent storage of metadata and encrypted file blobs. Follow these steps to set it up:

### 1. Create an RDS Instance
1. Log in to your **AWS Management Console**.
2. Navigate to **RDS** and click **"Create database"**.
3. Choose **"Standard create"**.
4. Engine options: **Microsoft SQL Server**.
5. Edition: **SQL Server Express** (Free Tier eligible).
6. Templates: **Free tier** (if applicable).
7. Settings:
   - **DB instance identifier**: `filefox-db`
   - **Master username**: `admin`
   - **Master password**: *Choose a strong password*
8. Connectivity:
   - **Public access**: **Yes** (if you want to access it from outside AWS VPC, ensure security groups allow port 1433).
   - **VPC security group**: Create new or choose existing. Ensure it allows inbound traffic on port **1433**.
9. Click **"Create database"**.

### 2. Configure Connection String
1. Once the RDS instance is "Available", click on it to see the **Endpoint**.
2. Open `appsettings.json` in the root of the project.
3. Update the `DefaultConnection` string:
   ```json
   "ConnectionStrings": {
     "DefaultConnection": "Server=YOUR_RDS_ENDPOINT,1433;Database=FileFoxDb;User Id=admin;Password=YOUR_PASSWORD;TrustServerCertificate=True"
   }
   ```
   - Replace `YOUR_RDS_ENDPOINT` with the endpoint from the AWS console.
   - Replace `YOUR_PASSWORD` with the master password you set.

### 3. Run the Application
The application is configured to automatically create the database schema on startup using `db.Database.EnsureCreated()`. No manual migrations are required for the initial setup.

### 4. Troubleshooting Connection Issues
If the application fails to start with a database connection error:
- **No such host is known**: Double-check the `Server` address in your connection string. It should match the Endpoint provided in the AWS Console.
- **Connection Timed Out**: Ensure your AWS RDS Security Group allows inbound traffic on port `1433`. If you are running locally, you may need to add your public IP address to the allowed list.
- **SSL/TLS errors**: Ensure `TrustServerCertificate=True` is included in the connection string if you are using self-signed certificates or RDS default certificates without installing them locally.
- **Foreign Key / NULL Errors**: If you encounter errors like `Cannot insert the value NULL into column 'FileRecordId'`, it means your database schema was created before the recent update. Since we use `EnsureCreated()`, you must **drop the `AuditLogs` table** (or the entire database) and restart the application to let it recreate the schema correctly.

## Security
- **Authentication**: JWT Bearer tokens are required for all file operations.
- **Authorization**: Users can only access their own files.
- **Encryption**: Files are expected to be encrypted client-side. The backend only stores ciphertext.
- **Metadata Encryption**: Clients can now provide `EncryptedMetadata` during file initialization. This field is stored as ciphertext on the server, ensuring even file-related metadata is private.
- **MFA Recovery**: When setting up MFA, the server provides 10 single-use recovery codes. These codes are hashed (using BCrypt) before being stored. Use the `POST /auth/login/recovery` endpoint if you lose access to your TOTP device.
- **File Recovery**: The `RecoveryWrappedKey` field allows storing a file key wrapped with a recovery public key, providing a secondary way to access files if primary keys are lost.
- **Rate Limiting**: API endpoints are protected by rate limiting. The `auth` endpoints are limited to 10 requests per minute, and other `api` endpoints are limited to 100 requests per minute.
- **Security Headers**: The API uses security headers (HSTS, CSP, etc.) to harden the server against common web attacks.
- **Auditing**: Critical actions like logins and file deletions are logged for security auditing.
