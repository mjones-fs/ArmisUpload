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

// File type validation disabled - accepting all file types

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + "-" + Date.now());
  },
});
const upload = multer({ 
  storage: storage,
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
  
  // Content Security Policy
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none';"
  );
  
  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Permissions Policy
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  next();
});

// Security: Request size limits
app.use(express.static("public"));
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

// Helper function to get or create a project named "Armis-{customer}"
async function getOrCreateArmisProject(apiKey, baseUrl, customer) {
  try {
    const projectName = customer ? `Armis-${customer}` : "Armis";
    
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
      return getResponse.data[0].id;
    }

    // Create new project if it doesn't exist
    console.log(`Creating new ${projectName} project...`);
    const createResponse = await axios.post(
      `${baseUrl}/public/v0/projects`,
      {
        name: projectName,
        description: `Armis device firmware uploads${customer ? ` for ${customer}` : ""}`,
        type: "firmware"
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

    console.log(`Created ${projectName} project:`, createResponse.data.id);
    return createResponse.data.id;
  } catch (error) {
    console.error("Error getting/creating project:", error.response?.data || error.message);
    throw error;
  }
}

// Helper function to create a version with the DeviceID
async function createVersionForDevice(apiKey, baseUrl, projectId, deviceId) {
  try {
    // Security: Validate projectId to prevent injection
    if (!projectId || typeof projectId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(projectId)) {
      throw new Error('Invalid project ID');
    }
    
    console.log(`Creating version for device ${deviceId}...`);
    const createResponse = await axios.post(
      `${baseUrl}/public/v0/projects/${projectId}/versions`,
      {
        version: deviceId,
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
    
    // Security: Validate and sanitize version (optional)
    const rawVersion = req.body.version;
    const version = rawVersion && rawVersion.trim() ? sanitizeDeviceId(rawVersion.trim()) : null;
    
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

    console.log(`Processing upload for device: ${deviceId}${customer ? ` (customer: ${customer})` : ''}`);

    // Step 1: Get or create project with customer appended
    const projectId = await getOrCreateArmisProject(apiKey, baseUrl, customer);

    // Step 2: Create version named with DeviceID
    const projectVersionId = await createVersionForDevice(apiKey, baseUrl, projectId, deviceId);

    // Step 3: Upload file to scans endpoint
    if (DEBUG_MODE) {
      try {
        const st = fs.statSync(filePath);
        console.log(`DEBUG upload target: ${baseUrl}/public/v0/scans`);
        console.log(`DEBUG file: ${filename}, size=${st.size} bytes, proxy=${USE_PROXY}`);
      } catch {}
    }

    console.log(`Uploading file to scan endpoint...`);
    
    // Read file as buffer for octet-stream upload
    const fileBuffer = fs.readFileSync(filePath);

    const scanTypes = ["sca", "sast", "config", "vulnerability_analysis"];

    const scanResponse = await axios.post(
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

    // Clean up uploaded file
    fs.unlinkSync(filePath);

    console.log("Scan triggered successfully");
    res.json({ 
      success: true, 
      projectId: projectId,
      projectVersionId: projectVersionId,
      message: "File uploaded and scan triggered successfully",
      data: scanResponse.data 
    });
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
