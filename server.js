import express from "express";
import multer from "multer";
import axios from "axios";
import FormData from "form-data";
import fs from "fs";
import dotenv from "dotenv";
import path from "path";
import https from "https";

dotenv.config();

const app = express();

// Debug and network configuration
const DEBUG_MODE = process.env.DEBUG === 'true' || process.env.DEBUG === '1';
const USE_PROXY = process.env.USE_PROXY !== 'false'; // set USE_PROXY=false to disable env proxy

// HTTPS agent for all outbound API calls
const httpsAgent = new https.Agent({
  keepAlive: true,
  minVersion: 'TLSv1.2',
  // For debugging TLS issues you can set NODE_ENV!=='production' to skip cert verification.
  // Do not set this to false in production.
  rejectUnauthorized: process.env.NODE_ENV === 'production'
});

// Security: Input validation and sanitization functions
function sanitizeDeviceId(deviceId) {
  if (!deviceId || typeof deviceId !== 'string') {
    return null;
  }
  
  // Remove any whitespace
  let sanitized = deviceId.trim();
  
  // Limit length (reasonable limit for device IDs)
  if (sanitized.length > 255) {
    return null;
  }
  
  // Only allow alphanumeric, hyphens, underscores, and dots
  // This prevents injection attacks while allowing common device ID formats
  if (!/^[a-zA-Z0-9._-]+$/.test(sanitized)) {
    return null;
  }
  
  return sanitized;
}

function sanitizeName(name) {
  if (!name || typeof name !== 'string') {
    return null;
  }
  
  // Remove any whitespace from beginning/end
  let sanitized = name.trim();
  
  // Limit length
  if (sanitized.length > 255 || sanitized.length < 1) {
    return null;
  }
  
  // Remove control characters but allow spaces, letters, numbers, and common punctuation
  sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');
  
  return sanitized;
}

function validateEmail(email) {
  if (!email || typeof email !== 'string') {
    return false;
  }
  
  // Trim whitespace
  const trimmed = email.trim();
  
  // Limit length
  if (trimmed.length > 255) {
    return false;
  }
  
  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(trimmed);
}

function sanitizeFilename(filename) {
  if (!filename || typeof filename !== 'string') {
    return 'uploaded-file';
  }
  
  // Get just the basename to prevent path traversal
  const basename = path.basename(filename);
  
  // Remove any null bytes
  let sanitized = basename.replace(/\0/g, '');
  
  // Remove any control characters
  sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');
  
  // Limit length
  if (sanitized.length > 255) {
    const ext = path.extname(sanitized);
    sanitized = sanitized.substring(0, 255 - ext.length) + ext;
  }
  
  // If empty after sanitization, use default
  if (!sanitized || sanitized === '.' || sanitized === '..') {
    return 'uploaded-file';
  }
  
  return sanitized;
}

// Security: File type validation - allow common firmware and binary file types
// Note: Firmware files can have various formats, so we use a permissive whitelist
const ALLOWED_MIME_TYPES = [
  'application/octet-stream', // Generic binary (most common for firmware)
  'application/x-executable',
  'application/x-elf',
  'application/x-sharedlib',
  'application/x-archive',
  'application/zip',
  'application/x-tar',
  'application/gzip',
  'application/x-gzip',
  'application/x-xz',
  'application/x-7z-compressed',
  'application/x-vmdk',
  'application/x-virtualbox-vdi',
  'application/x-qemu-disk',
  'application/x-iso9660-image',
  'image/x-iso9660-image',
  'application/vnd.ms-cab-compressed',
  'application/x-rpm',
  'application/x-debian-package',
  'application/vnd.android.package-archive',
  'application/json', // SBOM files
  'text/xml', // SBOM files
  'application/xml', // SBOM files
];

const ALLOWED_EXTENSIONS = [
  '.bin', '.elf', '.hex', '.img', '.fw', '.firmware', '.rom', '.dmp',
  '.zip', '.tar', '.gz', '.tgz', '.xz', '.7z', '.rar', '.bz2',
  '.so', '.a', '.o', '.dll', '.exe', '.dylib', '.lib',
  '.vmdk', '.ova', '.vdi', '.qcow', '.qcow2', '.iso', '.vhd', '.vhdx', '.vpc',
  '.rpm', '.deb', '.apk', '.cab', '.msi',
  '.cpio', '.squashfs', '.cramfs', '.jffs2', '.ubifs',
];

// SBOM file extensions
const SBOM_EXTENSIONS = [
  '.bom.json', '.cdx.json', '.bom.xml', '.cdx.xml', // CycloneDX formats
  '.spdx.json', '.spdx', // SPDX formats
  '.json', '.xml', // Generic formats (will default to CycloneDX)
];

function validateFileType(file) {
  // Check MIME type if provided
  if (file.mimetype) {
    // application/octet-stream is allowed (common for firmware)
    // but we still validate by extension
    if (file.mimetype !== 'application/octet-stream' && !ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return false;
    }
  }
  
  // Check file extension (required for validation)
  const ext = path.extname(file.originalname || '').toLowerCase();
  const filename = (file.originalname || '').toLowerCase();
  
  if (!ext) {
    // No extension - reject unless MIME type is explicitly allowed
    if (file.mimetype && ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return true;
    }
    return false;
  }
  
  // Check if it's an SBOM file (including compound extensions)
  if (isSbomFile(filename)) {
    return true;
  }
  
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return false;
  }
  
  return true;
}

// Helper function to detect SBOM files by extension
function isSbomFile(filename) {
  if (!filename || typeof filename !== 'string') {
    return false;
  }
  
  const lowerFilename = filename.toLowerCase();
  
  // Check compound extensions first (e.g., .bom.json, .cdx.xml)
  for (const ext of SBOM_EXTENSIONS) {
    if (lowerFilename.endsWith(ext)) {
      return true;
    }
  }
  
  return false;
}

// Helper function to determine SBOM type from filename
function getSbomType(filename) {
  if (!filename || typeof filename !== 'string') {
    return 'cdx'; // Default to CycloneDX
  }
  
  const lowerFilename = filename.toLowerCase();
  
  // Check for SPDX indicators
  if (lowerFilename.includes('spdx') || lowerFilename.endsWith('.spdx') || lowerFilename.endsWith('.spdx.json')) {
    return 'spdx';
  }
  
  // Default to CycloneDX for all other cases
  // (including .bom.json, .cdx.json, .bom.xml, .cdx.xml, .json, .xml)
  return 'cdx';
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    // Security: Use timestamp-based filename to prevent conflicts and path issues
    cb(null, file.fieldname + "-" + Date.now());
  },
});

const upload = multer({ 
  storage: storage,
  fileFilter: function (req, file, cb) {
    // Security: Validate file type before accepting upload
    if (validateFileType(file)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Allowed types: firmware, binary, archive, VM image, and SBOM files (.json, .xml, .spdx, .cdx, .bom).`), false);
    }
  },
  limits: { 
    fileSize: 50 * 1024 * 1024 * 1024, // 50GB
    fieldSize: 1024, // Limit field size to 1KB
  }
});

// Security: Security headers middleware
app.use((req, res, next) => {
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // XSS Protection (legacy, but still useful)
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Content Security Policy - strict policy to prevent XSS
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " + // unsafe-inline needed for inline scripts in HTML
    "style-src 'self' 'unsafe-inline'; " + // unsafe-inline needed for inline styles in HTML
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self';"
  );
  
  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions Policy (formerly Feature-Policy)
  res.setHeader('Permissions-Policy', 
    'geolocation=(), ' +
    'microphone=(), ' +
    'camera=(), ' +
    'payment=(), ' +
    'usb=(), ' +
    'magnetometer=(), ' +
    'gyroscope=(), ' +
    'accelerometer=()'
  );
  
  // Strict Transport Security (HSTS) - only set if using HTTPS
  // Note: Only set this header if the application is served over HTTPS
  // res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // Prevent DNS prefetching
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  
  // Prevent IE from executing downloads in site context
  res.setHeader('X-Download-Options', 'noopen');
  
  next();
});

// Security: Request size limits
// Note: Static files are served from public directory
app.use(express.static("public", {
  // Security: Disable directory listing but allow index.html
  index: 'index.html',
  // Security: Set cache control for static assets
  setHeaders: (res, path) => {
    // Don't cache HTML files to ensure updates are reflected
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));
app.use(express.urlencoded({ extended: true, limit: '1mb' })); // Limit URL-encoded bodies
app.use(express.json({ limit: '1mb' })); // Limit JSON bodies

// Security: Simple rate limiting (in-memory, for production use redis-based solution)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 10; // 10 uploads per 15 minutes per IP

function rateLimitMiddleware(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  
  // Clean up old entries
  if (rateLimitStore.size > 10000) {
    for (const [key, value] of rateLimitStore.entries()) {
      if (now - value.firstRequest > RATE_LIMIT_WINDOW) {
        rateLimitStore.delete(key);
      }
    }
  }
  
  const record = rateLimitStore.get(ip);
  
  if (!record) {
    rateLimitStore.set(ip, {
      count: 1,
      firstRequest: now,
      resetTime: now + RATE_LIMIT_WINDOW
    });
    return next();
  }
  
  // Reset if window expired
  if (now - record.firstRequest > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(ip, {
      count: 1,
      firstRequest: now,
      resetTime: now + RATE_LIMIT_WINDOW
    });
    return next();
  }
  
  // Check limit
  if (record.count >= RATE_LIMIT_MAX_REQUESTS) {
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);
    return res.status(429).json({ 
      error: 'Too many requests. Please try again later.',
      retryAfter: retryAfter
    });
  }
  
  record.count++;
  next();
}

// Helper function to get or create a folder named after the customer
async function getOrCreateFolder(apiKey, baseUrl, customer) {
  if (!customer) {
    return null; // No folder if no customer specified
  }

  try {
    const folderName = customer;
    
    // Search for existing folder
    const getResponse = await axios.get(`${baseUrl}/public/v0/folders`, {
      headers: {
        "X-Authorization": apiKey,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      params: {
        filter: `name=="${folderName}"`
      },
      httpsAgent,
      proxy: USE_PROXY ? undefined : false,
      timeout: 60000
    });

    if (getResponse.data && getResponse.data.length > 0) {
      console.log(`Found existing folder "${folderName}":`, getResponse.data[0].id);
      return String(getResponse.data[0].id); // Ensure folderId is a string
    }

    // Create new folder if it doesn't exist
    console.log(`Creating new folder "${folderName}"...`);
    const createResponse = await axios.post(
      `${baseUrl}/public/v0/folders`,
      {
        name: folderName,
        description: `Folder for Armis device firmware uploads for ${customer}`
      },
      {
        headers: {
          "X-Authorization": apiKey,
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        httpsAgent,
        proxy: USE_PROXY ? undefined : false,
        timeout: 60000
      }
    );

    console.log(`Created folder "${folderName}":`, createResponse.data.id);
    return String(createResponse.data.id); // Ensure folderId is a string
  } catch (error) {
    console.error("Error getting/creating folder:", error.response?.data || error.message);
    throw error;
  }
}

// Helper function to get or create a project named after the Device ID
async function getOrCreateArmisProject(apiKey, baseUrl, deviceId, customer, name, email) {
  try {
    const projectName = deviceId;
    
    // Get or create folder for customer (if customer is provided)
    const folderId = await getOrCreateFolder(apiKey, baseUrl, customer);
    
    // Search for existing project
    const getResponse = await axios.get(`${baseUrl}/public/v0/projects`, {
      headers: {
        "X-Authorization": apiKey,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      params: {
        filter: `name=="${projectName}"`
      },
      httpsAgent,
      proxy: USE_PROXY ? undefined : false,
      timeout: 60000
    });

    if (getResponse.data && getResponse.data.length > 0) {
      console.log(`Found existing ${projectName} project:`, getResponse.data[0].id);
      // If project exists but folderId was provided, ensure it's in the folder
      if (folderId) {
        try {
          await axios.put(
            `${baseUrl}/public/v0/folders/${folderId}/projects`,
            [getResponse.data[0].id],
            {
              headers: {
                "X-Authorization": apiKey,
                "Content-Type": "application/json",
                "Accept": "application/json"
              },
              httpsAgent,
              proxy: USE_PROXY ? undefined : false,
              timeout: 60000
            }
          );
          console.log(`Assigned existing project to folder "${customer}"`);
        } catch (folderError) {
          // Log but don't fail if folder assignment fails
          console.warn("Warning: Could not assign existing project to folder:", folderError.response?.data || folderError.message);
        }
      }
      return getResponse.data[0].id;
    }

    // Create new project if it doesn't exist
    console.log(`Creating new ${projectName} project...`);
    let description = `Armis device firmware uploads${customer ? ` for ${customer}` : ""}`;
    if (name && email) {
      description += `, Contact name: ${name}, ${email}`;
    }
    const projectData = {
      name: projectName,
      description: description,
      type: "firmware"
    };
    
    // Add folderId if folder was created/found (ensure it's a string)
    if (folderId) {
      projectData.folderId = String(folderId);
      if (DEBUG_MODE) {
        console.log(`DEBUG: Creating project with folderId: ${projectData.folderId} (type: ${typeof projectData.folderId})`);
      }
    }
    
    let createResponse;
    try {
      createResponse = await axios.post(
        `${baseUrl}/public/v0/projects`,
        projectData,
        {
          headers: {
            "X-Authorization": apiKey,
            "Content-Type": "application/json",
            "Accept": "application/json"
          },
          httpsAgent,
          proxy: USE_PROXY ? undefined : false,
          timeout: 60000
        }
      );
    } catch (createError) {
      // If creation with folderId fails, try without folderId and assign later
      if (folderId && createError.response?.status === 500) {
        console.warn(`Project creation with folderId failed, trying without folderId and assigning to folder after creation...`);
        let descriptionWithoutFolder = `Armis device firmware uploads${customer ? ` for ${customer}` : ""}`;
        if (name && email) {
          descriptionWithoutFolder += `, Contact name: ${name}, ${email}`;
        }
        const projectDataWithoutFolder = {
          name: projectName,
          description: descriptionWithoutFolder,
          type: "firmware"
        };
        
        createResponse = await axios.post(
          `${baseUrl}/public/v0/projects`,
          projectDataWithoutFolder,
          {
            headers: {
              "X-Authorization": apiKey,
              "Content-Type": "application/json",
              "Accept": "application/json"
            },
            httpsAgent,
            proxy: USE_PROXY ? undefined : false,
            timeout: 60000
          }
        );
        
        // Now assign to folder
        try {
          await axios.put(
            `${baseUrl}/public/v0/folders/${folderId}/projects`,
            [createResponse.data.id],
            {
              headers: {
                "X-Authorization": apiKey,
                "Content-Type": "application/json",
                "Accept": "application/json"
              },
              httpsAgent,
              proxy: USE_PROXY ? undefined : false,
              timeout: 60000
            }
          );
          console.log(`Project assigned to folder "${customer}" after creation`);
        } catch (folderError) {
          console.warn("Warning: Could not assign project to folder:", folderError.response?.data || folderError.message);
        }
      } else {
        // Re-throw if it's a different error or no folderId
        throw createError;
      }
    }

    console.log(`Created ${projectName} project:`, createResponse.data.id);
    if (folderId) {
      console.log(`Project assigned to folder "${customer}"`);
    }
    return createResponse.data.id;
  } catch (error) {
    console.error("Error getting/creating project:", {
      message: error.message,
      status: error.response?.status,
      statusText: error.response?.statusText,
      data: error.response?.data,
      folderId: folderId ? String(folderId) : null
    });
    throw error;
  }
}

// Helper function to create a version with the specified version value
async function createVersionForDevice(apiKey, baseUrl, projectId, version) {
  try {
    // Security: Validate projectId to prevent injection
    if (!projectId || typeof projectId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(projectId)) {
      throw new Error('Invalid project ID');
    }
    
    console.log(`Creating version ${version}...`);
    const createResponse = await axios.post(
      `${baseUrl}/public/v0/projects/${projectId}/versions`,
      {
        version: version,
        releaseType: "RELEASE"
      },
      {
        headers: {
          "X-Authorization": apiKey,
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        httpsAgent,
        proxy: USE_PROXY ? undefined : false,
        timeout: 60000
      }
    );

    console.log("Created version:", createResponse.data.id);
    return createResponse.data.id;
  } catch (error) {
    console.error("Error creating version:", error.response?.data || error.message);
    throw error;
  }
}

app.post("/upload", rateLimitMiddleware, upload.single("file"), async (req, res) => {
  let filePath = null;
  
  try {
    // Security: Validate file was uploaded
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }
    
    filePath = req.file.path;
    
    // Security: Validate and sanitize name
    const rawName = req.body.name;
    const name = sanitizeName(rawName);
    
    if (!name) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ 
        error: "Invalid Name. Name must be between 1 and 255 characters." 
      });
    }
    
    // Security: Validate email
    const rawEmail = req.body.email;
    if (!validateEmail(rawEmail)) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ 
        error: "Invalid Email Address. Please provide a valid email address." 
      });
    }
    const email = rawEmail.trim();
    
    // Security: Validate and sanitize deviceId
    const rawDeviceId = req.body.deviceId;
    const deviceId = sanitizeDeviceId(rawDeviceId);
    
    if (!deviceId) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ 
        error: "Invalid DeviceID. DeviceID must be alphanumeric and may contain dots, hyphens, or underscores. Maximum length is 255 characters." 
      });
    }
    
    // Security: Validate and sanitize version (required)
    const rawVersion = req.body.version;
    if (!rawVersion || !rawVersion.trim()) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ 
        error: "Version is required. Please provide a version value." 
      });
    }
    const version = sanitizeDeviceId(rawVersion.trim());
    
    if (!version) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ 
        error: "Invalid Version. Version must be alphanumeric and may contain dots, hyphens, or underscores. Maximum length is 255 characters." 
      });
    }
    
    // Security: Validate and sanitize customer
    const rawCustomer = req.body.customer;
    const customer = rawCustomer ? sanitizeDeviceId(rawCustomer) : null;
    
    // Security: Sanitize filename
    const rawFilename = req.file.originalname || req.file.filename;
    const filename = sanitizeFilename(rawFilename);
    
    const apiKey = process.env.API_KEY;
    const baseUrl = process.env.API_BASE_URL || "https://api.finitestate.io";
    
    // Security: Validate API key exists
    if (!apiKey) {
      fs.unlinkSync(filePath);
      return res.status(500).json({ error: "Server configuration error" });
    }

    console.log(`Processing upload for device: ${deviceId}, version: ${version}${customer ? ` (customer: ${customer})` : ''}`);

    // Step 1: Get or create project named after the Device ID
    const projectId = await getOrCreateArmisProject(apiKey, baseUrl, deviceId, customer, name, email);

    // Step 2: Create version named with the specified version value
    const projectVersionId = await createVersionForDevice(apiKey, baseUrl, projectId, version);

    // Step 3: Determine if file is SBOM or binary and upload to appropriate endpoint
    const isFileSbom = isSbomFile(filename);
    
    if (DEBUG_MODE) {
      try {
        const st = fs.statSync(filePath);
        const endpoint = isFileSbom ? `${baseUrl}/public/v0/scans/sbom` : `${baseUrl}/public/v0/scans`;
        console.log(`DEBUG upload target: ${endpoint}`);
        console.log(`DEBUG file: ${filename}, size=${st.size} bytes, isSBOM=${isFileSbom}, proxy=${USE_PROXY}`);
      } catch {}
    }

    console.log(`Uploading ${isFileSbom ? 'SBOM' : 'binary'} file to scan endpoint...`);
    
    // Read file as buffer for octet-stream upload
    const fileBuffer = fs.readFileSync(filePath);

    let scanResponse;
    
    if (isFileSbom) {
      // Upload SBOM file
      const sbomType = getSbomType(filename);
      console.log(`SBOM type detected: ${sbomType}`);
      
      scanResponse = await axios.post(
        `${baseUrl}/public/v0/scans/sbom`,
        fileBuffer,
        {
          headers: {
            "X-Authorization": apiKey,
            "Accept": "application/json",
            "Content-Type": "application/octet-stream"
          },
          params: {
            projectVersionId: projectVersionId,
            filename: filename,
            type: sbomType
          },
          maxBodyLength: Infinity,
          maxContentLength: Infinity,
          httpsAgent,
          proxy: USE_PROXY ? undefined : false,
          timeout: 300000 // Increase timeout to 5 minutes for large files
        }
      );
    } else {
      // Upload binary file
      const scanTypes = ["sca", "sast", "config", "vulnerability_analysis"];
      
      scanResponse = await axios.post(
        `${baseUrl}/public/v0/scans`,
        fileBuffer,
        {
          headers: {
            "X-Authorization": apiKey,
            "Accept": "application/json",
            "Content-Type": "application/octet-stream"
          },
          params: {
            projectVersionId: projectVersionId,
            filename: filename,
            type: scanTypes
          },
          paramsSerializer: {
            indexes: null // This tells axios to repeat the parameter name for arrays: type=sca&type=sast&type=config&type=vulnerability_analysis
          },
          maxBodyLength: Infinity,
          maxContentLength: Infinity,
          httpsAgent,
          proxy: USE_PROXY ? undefined : false,
          timeout: 300000 // Increase timeout to 5 minutes for large files
        }
      );
    }

    // Clean up uploaded file
    fs.unlinkSync(filePath);

    console.log("Scan triggered successfully");
    
    // SBOM endpoint returns 204 with no data, binary endpoint returns 200 with data
    const responseData = {
      success: true, 
      projectId: projectId,
      projectVersionId: projectVersionId,
      message: `${isFileSbom ? 'SBOM' : 'Binary'} file uploaded and scan triggered successfully`
    };
    
    // Only include scan data if it exists (binary scans return data, SBOM scans don't)
    if (scanResponse.data) {
      responseData.data = scanResponse.data;
    }
    
    res.json(responseData);
  } catch (error) {
    // Security: Log full error details server-side, but don't expose to client
    console.error("Upload error:", {
      message: error.message,
      code: error.code,
      errno: error.errno,
      syscall: error.syscall,
      cause: error.cause?.message,
      response: error.response?.data,
      status: error.response?.status,
      stack: process.env.NODE_ENV === 'development' || DEBUG_MODE ? error.stack : undefined
    });
    
    // Log detailed validation errors if present
    if (error.response?.data?.errors) {
      console.error("Validation errors:", JSON.stringify(error.response.data.errors, null, 2));
    }
    
    // Clean up file on error
    if (filePath) {
      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      } catch (unlinkError) {
        console.error("Error cleaning up file:", unlinkError);
      }
    }
    
    // Handle specific HTTP errors
    if (error.response) {
      const status = error.response.status;
      if (status === 413) {
        res.status(413).json({ 
          error: "File too large. Maximum file size is 50GB." 
        });
      } else if (status === 401 || status === 403) {
        res.status(status).json({ 
          error: "Authentication failed. Please check your API credentials." 
        });
      } else if (status === 429) {
        res.status(429).json({ 
          error: "Rate limit exceeded. Please try again later." 
        });
      } else {
        // Security: Don't expose API error details
        res.status(500).json({ 
          error: "Upload failed. Please try again later." 
        });
      }
    } else if (error.code === 'LIMIT_FILE_SIZE') {
      res.status(413).json({ 
        error: "File too large. Maximum file size is 50GB." 
      });
    } else if (error.message && error.message.includes('Invalid file type')) {
      // Security: Handle file type validation errors
      res.status(400).json({ 
        error: error.message 
      });
    } else {
      res.status(500).json({ error: "Upload failed. Please try again later." });
    }
  }
});

// Security: Check if uploads directory exists and has proper permissions
if (!fs.existsSync('uploads')) {
  console.error('ERROR: uploads directory does not exist.');
  console.error('Please create the uploads directory by running: mkdir uploads');
  process.exit(1);
}

// Security: Verify uploads directory is actually a directory
try {
  const stats = fs.statSync('uploads');
  if (!stats.isDirectory()) {
    console.error('ERROR: uploads exists but is not a directory.');
    process.exit(1);
  }
} catch (error) {
  console.error('ERROR: Cannot access uploads directory:', error.message);
  process.exit(1);
}

const server = app.listen(3000, () => console.log("Server running at http://localhost:3000"));

// Set server timeout to 30 minutes for large file uploads
server.timeout = 1800000;
server.keepAliveTimeout = 1800000;
server.headersTimeout = 1810000; // Slightly higher than keepAliveTimeout
