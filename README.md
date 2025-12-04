# Armis Upload Service

A Node.js service for uploading firmware files to the Finite State platform with automatic project and version management.

## Features

- Automatically creates or finds an "Armis" project
- Creates a new version for each device using the DeviceID as the version name
- Uploads firmware files to trigger SCA (Software Composition Analysis) scans
- Handles large file uploads (up to 50GB)

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

1. **Get or Create Project**: Searches for a project named "Armis". If not found, creates it with type "firmware"
2. **Create Version**: Creates a new version for the project using the provided DeviceID as the version name
3. **Upload & Scan**: Posts the file to the `/public/v0/scans` endpoint to trigger a security scan

## API Reference

### POST /upload

Upload a firmware file for security scanning.

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Fields:
  - `file` (file): The firmware file to upload
  - `deviceId` (string): The device identifier (will be used as version name)

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

## Scan Type

The service triggers an **SCA** (Software Composition Analysis) scan, which generates an SBOM (Software Bill of Materials) as CycloneDX JSON format.

## Error Handling

The service handles various error conditions:
- Missing DeviceID
- File too large (413)
- Network errors
- API authentication errors
- Invalid project/version parameters

## Notes

- Files are temporarily stored in the `uploads/` directory and automatically deleted after processing
- Each upload creates a new version in the "Armis" project
- The project type is set to "firmware" by default
- Large file uploads are supported with extended timeouts (30 minutes)
