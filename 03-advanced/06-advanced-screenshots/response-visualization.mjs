/**
 * PHASE 3: ADVANCED LEVEL
 * Module 6: Advanced Screenshots
 * Lesson 1: Response Visualization
 * 
 * Learning Objectives:
 * - Capture and visualize API responses
 * - Generate visual reports of API data
 * - Create response comparison visualizations
 * - Export API response snapshots
 */

import { expect } from "chai";
import supertest from "supertest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { getApiToken } from "../../../utils/env-loader.mjs";

console.log("=== RESPONSE VISUALIZATION ===");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const request = supertest("https://gorest.co.in/public-api/");
const TOKEN = getApiToken();

// Screenshots/Visualization Directory
const SCREENSHOTS_DIR = path.join(__dirname, "../../../screenshots");
if (!fs.existsSync(SCREENSHOTS_DIR)) {
  fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
}

// Response Visualizer
class ResponseVisualizer {
  constructor(outputDir) {
    this.outputDir = outputDir;
  }

  // Generate HTML visualization of response
  generateHTMLVisualization(response, filename) {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Response Visualization</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #4CAF50;
            padding-bottom: 10px;
        }
        .section {
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-left: 4px solid #4CAF50;
        }
        .status-code {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 4px;
            font-weight: bold;
            color: white;
        }
        .status-200 { background-color: #4CAF50; }
        .status-201 { background-color: #4CAF50; }
        .status-400 { background-color: #f44336; }
        .status-404 { background-color: #ff9800; }
        .status-500 { background-color: #f44336; }
        pre {
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 14px;
        }
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }
        .metadata-item {
            padding: 10px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .metadata-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }
        .metadata-value {
            font-size: 16px;
            font-weight: bold;
            color: #333;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>API Response Visualization</h1>
        
        <div class="section">
            <h2>Request Information</h2>
            <div class="metadata">
                <div class="metadata-item">
                    <div class="metadata-label">Method</div>
                    <div class="metadata-value">${response.request?.method || 'GET'}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">URL</div>
                    <div class="metadata-value">${response.request?.url || 'N/A'}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Status Code</div>
                    <div class="metadata-value">
                        <span class="status-code status-${response.status}">${response.status}</span>
                    </div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Response Time</div>
                    <div class="metadata-value">${response.responseTime || 'N/A'}ms</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Response Headers</h2>
            <pre>${JSON.stringify(response.headers, null, 2)}</pre>
        </div>
        
        <div class="section">
            <h2>Response Body</h2>
            <pre>${JSON.stringify(response.body, null, 2)}</pre>
        </div>
        
        <div class="section">
            <h2>Response Statistics</h2>
            <div class="metadata">
                <div class="metadata-item">
                    <div class="metadata-label">Data Items</div>
                    <div class="metadata-value">${Array.isArray(response.body?.data) ? response.body.data.length : response.body?.data ? 1 : 0}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Response Size</div>
                    <div class="metadata-value">${JSON.stringify(response.body).length} bytes</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
    `;

    const filePath = path.join(this.outputDir, `${filename}.html`);
    fs.writeFileSync(filePath, html);
    console.log(`✅ HTML visualization saved: ${filePath}`);
    return filePath;
  }

  // Generate JSON snapshot
  generateJSONSnapshot(response, filename) {
    const snapshot = {
      timestamp: new Date().toISOString(),
      request: {
        method: response.request?.method || 'GET',
        url: response.request?.url || '',
        headers: response.request?.headers || {}
      },
      response: {
        status: response.status,
        headers: response.headers,
        body: response.body,
        responseTime: response.responseTime
      }
    };

    const filePath = path.join(this.outputDir, `${filename}.json`);
    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2));
    console.log(`✅ JSON snapshot saved: ${filePath}`);
    return filePath;
  }

  // Compare two responses visually
  compareResponses(response1, response2, filename) {
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Response Comparison</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
        }
        .comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 20px 0;
        }
        .response-box {
            padding: 15px;
            background: #f9f9f9;
            border-radius: 4px;
            border: 2px solid #ddd;
        }
        .response-box h3 {
            margin-top: 0;
            color: #333;
        }
        .diff {
            background: #fff3cd;
            padding: 2px 4px;
            border-radius: 2px;
        }
        pre {
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Response Comparison</h1>
        <div class="comparison">
            <div class="response-box">
                <h3>Response 1</h3>
                <p><strong>Status:</strong> ${response1.status}</p>
                <p><strong>Time:</strong> ${response1.responseTime || 'N/A'}ms</p>
                <pre>${JSON.stringify(response1.body, null, 2)}</pre>
            </div>
            <div class="response-box">
                <h3>Response 2</h3>
                <p><strong>Status:</strong> ${response2.status}</p>
                <p><strong>Time:</strong> ${response2.responseTime || 'N/A'}ms</p>
                <pre>${JSON.stringify(response2.body, null, 2)}</pre>
            </div>
        </div>
    </div>
</body>
</html>
    `;

    const filePath = path.join(this.outputDir, `${filename}.html`);
    fs.writeFileSync(filePath, html);
    console.log(`✅ Comparison visualization saved: ${filePath}`);
    return filePath;
  }
}

// Test Scenarios
async function testResponseVisualization() {
  console.log("\n📸 Test 1: Generate Response Visualization");
  
  const visualizer = new ResponseVisualizer(SCREENSHOTS_DIR);
  
  const response = await request
    .get("/users")
    .set("Authorization", `Bearer ${TOKEN}`);
  
  response.responseTime = Date.now(); // Simulated
  
  const htmlPath = visualizer.generateHTMLVisualization(
    response,
    `users-response-${Date.now()}`
  );
  
  const jsonPath = visualizer.generateJSONSnapshot(
    response,
    `users-snapshot-${Date.now()}`
  );
  
  expect(fs.existsSync(htmlPath)).to.be.true;
  expect(fs.existsSync(jsonPath)).to.be.true;
  
  console.log("✅ Response visualization generated");
}

async function testUserDetailVisualization() {
  console.log("\n📸 Test 2: User Detail Visualization");
  
  // Create a user first
  const newUser = {
    name: "Visualization Test User",
    email: `viztest${Date.now()}@example.com`,
    gender: "male",
    status: "active"
  };
  
  const createResponse = await request
    .post("/users")
    .set("Authorization", `Bearer ${TOKEN}`)
    .send(newUser);
  
  const userId = createResponse.body.data.id;
  
  // Get user details
  const getResponse = await request
    .get(`/users/${userId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
  
  getResponse.responseTime = Date.now();
  
  const visualizer = new ResponseVisualizer(SCREENSHOTS_DIR);
  visualizer.generateHTMLVisualization(
    getResponse,
    `user-detail-${userId}`
  );
  
  // Cleanup
  await request
    .delete(`/users/${userId}`)
    .set("Authorization", `Bearer ${TOKEN}`);
  
  console.log("✅ User detail visualization generated");
}

async function testResponseComparison() {
  console.log("\n📸 Test 3: Response Comparison");
  
  const visualizer = new ResponseVisualizer(SCREENSHOTS_DIR);
  
  // Get two different responses
  const response1 = await request
    .get("/users?page=1")
    .set("Authorization", `Bearer ${TOKEN}`);
  
  const response2 = await request
    .get("/users?page=2")
    .set("Authorization", `Bearer ${TOKEN}`);
  
  response1.responseTime = Date.now();
  response2.responseTime = Date.now();
  
  visualizer.compareResponses(
    response1,
    response2,
    `comparison-${Date.now()}`
  );
  
  console.log("✅ Response comparison generated");
}

// Run all tests
(async () => {
  try {
    await testResponseVisualization();
    await testUserDetailVisualization();
    await testResponseComparison();
    
    console.log("\n✅ All visualization tests completed!");
    console.log(`📁 Screenshots saved to: ${SCREENSHOTS_DIR}`);
  } catch (error) {
    console.error("❌ Visualization test failed:", error.message);
    process.exit(1);
  }
})();

