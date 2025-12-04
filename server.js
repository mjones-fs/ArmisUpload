import express from "express";
import multer from "multer";
import axios from "axios";
import fs from "fs";
import dotenv from "dotenv";

dotenv.config();

const app = express();
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
  limits: { fileSize: 50 * 1024 * 1024 * 1024 } // 50GB
});

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// Helper function to get or create a project named "Armis"
async function getOrCreateArmisProject(apiKey, baseUrl) {
  try {
    // Search for existing "Armis" project
    const getResponse = await axios.get(`${baseUrl}/public/v0/projects`, {
      headers: {
        "X-Authorization": apiKey,
        "Content-Type": "application/json"
      },
      params: {
        filter: 'name=="Armis"'
      }
    });

    if (getResponse.data && getResponse.data.length > 0) {
      console.log("Found existing Armis project:", getResponse.data[0].id);
      return getResponse.data[0].id;
    }

    // Create new "Armis" project if it doesn't exist
    console.log("Creating new Armis project...");
    const createResponse = await axios.post(
      `${baseUrl}/public/v0/projects`,
      {
        name: "Armis",
        description: "Armis device firmware uploads",
        type: "firmware"
      },
      {
        headers: {
          "X-Authorization": apiKey,
          "Content-Type": "application/json"
        }
      }
    );

    console.log("Created Armis project:", createResponse.data.id);
    return createResponse.data.id;
  } catch (error) {
    console.error("Error getting/creating project:", error.response?.data || error.message);
    throw error;
  }
}

// Helper function to create a version with the DeviceID
async function createVersionForDevice(apiKey, baseUrl, projectId, deviceId) {
  try {
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
          "Content-Type": "application/json"
        }
      }
    );

    console.log("Created version:", createResponse.data.id);
    return createResponse.data.id;
  } catch (error) {
    console.error("Error creating version:", error.response?.data || error.message);
    throw error;
  }
}

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const filePath = req.file.path;
    const deviceId = req.body.deviceId;
    const filename = req.file.originalname || req.file.filename;
    
    const apiKey = process.env.API_KEY;
    const baseUrl = process.env.API_BASE_URL || "https://api.finitestate.io";

    if (!deviceId) {
      fs.unlinkSync(filePath);
      return res.status(400).json({ error: "DeviceID is required" });
    }

    console.log(`Processing upload for device: ${deviceId}`);

    // Step 1: Get or create "Armis" project
    const projectId = await getOrCreateArmisProject(apiKey, baseUrl);

    // Step 2: Create version named with DeviceID
    const projectVersionId = await createVersionForDevice(apiKey, baseUrl, projectId, deviceId);

    // Step 3: Upload file to scans endpoint
    console.log(`Uploading file to scan endpoint...`);
    const scanResponse = await axios.post(
      `${baseUrl}/public/v0/scans`,
      fs.createReadStream(filePath),
      {
        headers: {
          "X-Authorization": apiKey,
          "Content-Type": "application/octet-stream"
        },
        params: {
          projectVersionId: projectVersionId,
          filename: filename,
          type: "sca"
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity
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
    console.error("Upload error:", error.response?.data || error.message);
    
    // Clean up file on error
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        console.error("Error cleaning up file:", unlinkError);
      }
    }
    
    // Handle specific HTTP errors
    if (error.response) {
      const status = error.response.status;
      if (status === 413) {
        res.status(413).json({ 
          error: "File too large. The API server has a file size limit. Contact your administrator to increase the nginx client_max_body_size setting." 
        });
      } else {
        res.status(status).json({ 
          error: `Upload failed: ${error.response.data?.message || error.response.statusText || 'Unknown error'}`,
          details: error.response.data
        });
      }
    } else {
      res.status(500).json({ error: "Upload failed: Network error" });
    }
  }
});

const server = app.listen(3000, () => console.log("Server running at http://localhost:3000"));

// Set server timeout to 30 minutes for large file uploads
server.timeout = 1800000;
server.keepAliveTimeout = 1800000;
server.headersTimeout = 1810000; // Slightly higher than keepAliveTimeout
