# Armis Upload Service

A Node.js service for uploading firmware files to the Finite State platform with automatic project and version management.

## Features

- Automatically creates or finds a project named after the Device ID
- Creates or finds a folder for the customer (if provided)
- Creates a new version for each upload using the specified version value
- Uploads firmware files to trigger multiple security scans (SCA, SAST, Config, and Vulnerability Analysis)
- Handles large file uploads (up to 50GB)
- Comprehensive security controls including input validation, file type validation, rate limiting, and security headers
- Web UI with drag-and-drop file upload support

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API credentials
```

3. Create uploads directory:
```bash
mkdir uploads
```

4. Start the server:
```bash
node server.js
```

The server will run on `http://localhost:3000`

### URL parameters for the web UI

When you open the site, you can include CUSTOMER and DEVICE in the URL to pre-populate the form and display the customer name:
```
http://localhost:3000/?CUSTOMER=MyCustomer&DEVICE=device-123
```

- `CUSTOMER`: Optional. Shown at the top of the form.
- `DEVICE`: Optional. Pre-fills and locks the Device ID field. Remove it from the URL if you want to edit the Device ID manually.

## API Workflow

When a file is uploaded via the `/upload` endpoint, the service performs the following steps:

1. **Validate Input**: Validates and sanitizes all input fields (name, email, deviceId, version, customer)
2. **Validate File Type**: Ensures the uploaded file is a valid firmware, binary, archive, or VM image file
3. **Get or Create Folder**: If a customer is provided, searches for or creates a folder named after the customer
4. **Get or Create Project**: Searches for a project named after the Device ID. If not found, creates it with type "firmware" and assigns it to the customer folder (if provided)
5. **Create Version**: Creates a new version for the project using the provided version value
6. **Upload & Scan**: Posts the file to the `/public/v0/scans` endpoint to trigger multiple security scans (SCA, SAST, Config, and Vulnerability Analysis)
7. **Cleanup**: Automatically deletes the temporary uploaded file

## API Reference

### POST /upload

Upload a firmware file for security scanning.

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Fields:
  - `file` (file, required): The firmware file to upload (must be a valid firmware, binary, archive, or VM image file)
  - `name` (string, required): Contact name (1-255 characters)
  - `email` (string, required): Contact email address (valid email format)
  - `deviceId` (string, required): The device identifier (alphanumeric, dots, hyphens, underscores only, max 255 chars)
  - `version` (string, required): Version identifier (alphanumeric, dots, hyphens, underscores only, max 255 chars)
  - `customer` (string, optional): Customer identifier (alphanumeric, dots, hyphens, underscores only, max 255 chars)

**Response:**
```json
{
  "success": true,
  "projectId": "1234567890123456789",
  "projectVersionId": "9876543210987654321",
  "message": "File uploaded and scan triggered successfully",
  "data": {}
}
```

**Error Response:**
```json
{
  "error": "Error message",
  "details": {}
}
```

## Environment Variables

- `API_KEY`: Your Finite State API key (required)
- `API_BASE_URL`: Base URL for the Finite State API (default: https://api.finitestate.io)
- `DEBUG`: Set to `true` or `1` to enable debug logging (optional, default: false)
- `USE_PROXY`: Set to `false` to disable proxy usage from environment variables (optional, default: true)
- `NODE_ENV`: Node.js environment (e.g., `production`, `development`). In production, TLS certificate verification is enforced.

## Security Features

The application implements comprehensive security controls:

- **Input Validation**: All user inputs are validated and sanitized to prevent injection attacks
- **File Type Validation**: Only firmware, binary, archive, and VM image files are accepted
- **File Size Limits**: Maximum file size of 50GB with configurable limits
- **Rate Limiting**: 10 uploads per 15 minutes per IP address
- **Security Headers**: Comprehensive security headers including CSP, X-Frame-Options, and more
- **Path Traversal Prevention**: Filenames are sanitized to prevent directory traversal attacks
- **XSS Prevention**: Client-side and server-side XSS protections
- **Secure Error Handling**: Error messages don't expose sensitive information
- **TLS/HTTPS**: TLS 1.2+ with certificate verification in production

See `SECURITY_AUDIT.md` for detailed security information.

## Example Usage

### Using curl:
```bash
curl -X POST http://localhost:3000/upload \
  -F "file=@/path/to/firmware.bin" \
  -F "deviceId=device-12345"
```

### Using an HTML form:
```html
<form action="http://localhost:3000/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file" required />
  <input type="text" name="deviceId" placeholder="Device ID" required />
  <button type="submit">Upload</button>
</form>
```

## Scan Types

The service triggers multiple security scans for each uploaded file:

- **SCA** (Software Composition Analysis): Generates an SBOM (Software Bill of Materials) as CycloneDX JSON format
- **SAST** (Static Application Security Testing): Analyzes source code for security vulnerabilities
- **Config** (Configuration Analysis): Examines configuration files and settings for security issues
- **Vulnerability Analysis**: Performs comprehensive vulnerability assessment

## Error Handling

The service handles various error conditions:
- Missing DeviceID
- File too large (413)
- Network errors
- API authentication errors
- Invalid project/version parameters

## Notes

- Files are temporarily stored in the `uploads/` directory and automatically deleted after processing (success or failure)
- Each upload creates a new version in the project named after the Device ID
- Projects are automatically created if they don't exist and assigned to customer folders (if customer is provided)
- The project type is set to "firmware" by default
- Large file uploads are supported with extended timeouts (30 minutes)
- Version field can be auto-populated from filename patterns (e.g., v1.2.3, version-1.2.3, etc.)
- The web UI supports drag-and-drop file uploads with progress tracking
