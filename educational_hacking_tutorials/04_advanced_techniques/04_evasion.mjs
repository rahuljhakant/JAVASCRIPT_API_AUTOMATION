/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 4: Advanced Techniques
 * Lesson 4: Evasion Techniques
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand evasion techniques
 * - Learn signature evasion
 * - Practice behavioral evasion
 * - Learn defensive evasion detection
 */

import { expect } from "chai";
import supertest from "supertest";
import crypto from "crypto";

console.log("=== EVASION TECHNIQUES ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Evasion Framework
class EvasionFramework {
  constructor() {
    this.techniques = [];
    this.testResults = [];
  }

  testSignatureEvasion(originalPayload, evasionMethods) {
    console.log(`\n🔍 Testing Signature Evasion`);
    
    const results = {
      original: originalPayload,
      evasions: [],
      successful: []
    };
    
    for (const method of evasionMethods) {
      let evadedPayload = originalPayload;
      
      switch (method) {
        case "Encoding":
          evadedPayload = encodeURIComponent(originalPayload);
          break;
        case "Double Encoding":
          evadedPayload = encodeURIComponent(encodeURIComponent(originalPayload));
          break;
        case "Unicode Encoding":
          evadedPayload = originalPayload.split("").map(c => 
            `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`
          ).join("");
          break;
        case "Base64 Encoding":
          evadedPayload = Buffer.from(originalPayload).toString("base64");
          break;
        case "Hex Encoding":
          evadedPayload = originalPayload.split("").map(c => 
            `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`
          ).join("");
          break;
        case "Case Variation":
          evadedPayload = originalPayload.split("").map((c, i) => 
            i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()
          ).join("");
          break;
        case "Whitespace Insertion":
          evadedPayload = originalPayload.split("").join(" ");
          break;
        case "Comment Insertion":
          evadedPayload = originalPayload.replace(/(\w)/g, "$1/*comment*/");
          break;
      }
      
      results.evasions.push({
        method,
        payload: evadedPayload.substring(0, 100),
        description: `Payload evaded using ${method}`
      });
    }
    
    this.techniques.push(results);
    return results;
  }

  testBehavioralEvasion(behavior, evasionMethods) {
    console.log(`\n🔍 Testing Behavioral Evasion`);
    
    const results = {
      behavior,
      evasions: [],
      successful: []
    };
    
    const methods = [
      {
        name: "Time Delays",
        description: "Add delays between actions to avoid rate-based detection",
        implementation: "setTimeout(() => action(), delay)"
      },
      {
        name: "Request Throttling",
        description: "Limit request rate to stay below thresholds",
        implementation: "Rate limit requests to N per second"
      },
      {
        name: "User Agent Rotation",
        description: "Rotate user agents to avoid fingerprinting",
        implementation: "Randomly select from user agent pool"
      },
      {
        name: "IP Rotation",
        description: "Use proxy or VPN to rotate IP addresses",
        implementation: "Route requests through proxy pool"
      },
      {
        name: "Session Management",
        description: "Use different sessions for different actions",
        implementation: "Maintain multiple session tokens"
      },
      {
        name: "Traffic Normalization",
        description: "Make malicious traffic look like normal traffic",
        implementation: "Match normal traffic patterns"
      }
    ];
    
    for (const method of methods) {
      results.evasions.push({
        ...method,
        tested: true
      });
    }
    
    this.techniques.push(results);
    return results;
  }

  testEncodingTechniques(payload) {
    console.log(`\n🔍 Testing Encoding Techniques`);
    
    const encodings = {
      url: encodeURIComponent(payload),
      doubleUrl: encodeURIComponent(encodeURIComponent(payload)),
      base64: Buffer.from(payload).toString("base64"),
      hex: payload.split("").map(c => c.charCodeAt(0).toString(16)).join(""),
      unicode: payload.split("").map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join(""),
      html: payload
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;"),
      htmlDecimal: payload.split("").map(c => `&#${c.charCodeAt(0)};`).join(""),
      htmlHex: payload.split("").map(c => `&#x${c.charCodeAt(0).toString(16)};`).join("")
    };
    
    return encodings;
  }

  testPolymorphism(originalPayload) {
    console.log(`\n🔍 Testing Polymorphism`);
    
    const variants = [];
    
    // Generate polymorphic variants
    const transformations = [
      {
        name: "Case Variation",
        transform: (p) => p.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join("")
      },
      {
        name: "Whitespace Variation",
        transform: (p) => p.split("").join(" ")
      },
      {
        name: "Comment Insertion",
        transform: (p) => p.replace(/(\w)/g, "$1/*x*/")
      },
      {
        name: "String Concatenation",
        transform: (p) => p.split("").map(c => `"${c}"`).join("+")
      },
      {
        name: "Function Wrapping",
        transform: (p) => `eval("${p}")`
      }
    ];
    
    for (const transformation of transformations) {
      const variant = transformation.transform(originalPayload);
      variants.push({
        name: transformation.name,
        payload: variant.substring(0, 100),
        description: `Polymorphic variant using ${transformation.name}`
      });
    }
    
    return variants;
  }

  testAntiForensics() {
    console.log(`\n🔍 Testing Anti-Forensics Techniques`);
    
    const techniques = [
      {
        name: "Log Deletion",
        description: "Delete log files to remove evidence",
        detection: "Monitor log file deletions and use centralized logging"
      },
      {
        name: "Timestamp Manipulation",
        description: "Modify file timestamps to hide activity",
        detection: "Use file integrity monitoring and compare timestamps"
      },
      {
        name: "Memory-Only Execution",
        description: "Execute payloads in memory without writing to disk",
        detection: "Monitor process memory and use memory forensics"
      },
      {
        name: "Fileless Techniques",
        description: "Use legitimate tools for malicious purposes",
        detection: "Monitor command-line arguments and tool usage patterns"
      },
      {
        name: "Encryption",
        description: "Encrypt payloads and communications",
        detection: "Monitor encrypted traffic patterns and key exchange"
      }
    ];
    
    return techniques;
  }

  testDetectionAvoidance() {
    console.log(`\n🔍 Testing Detection Avoidance`);
    
    const techniques = [
      {
        name: "Sandbox Evasion",
        description: "Detect and evade sandbox environments",
        methods: [
          "Check for virtual machine indicators",
          "Delay execution",
          "Require user interaction",
          "Check system resources"
        ]
      },
      {
        name: "AV Evasion",
        description: "Evade antivirus detection",
        methods: [
          "Code obfuscation",
          "Packing",
          "Polymorphism",
          "Signature modification"
        ]
      },
      {
        name: "IDS/IPS Evasion",
        description: "Evade intrusion detection systems",
        methods: [
          "Packet fragmentation",
          "Protocol tunneling",
          "Traffic normalization",
          "Encoding"
        ]
      },
      {
        name: "EDR Evasion",
        description: "Evade endpoint detection and response",
        methods: [
          "Process injection",
          "Living off the land",
          "Legitimate tool abuse",
          "Memory-only execution"
        ]
      }
    ];
    
    return techniques;
  }

  generateEvasionReport() {
    console.log("\n📊 Evasion Techniques Report:");
    console.log("=" .repeat(50));
    
    console.log(`Total Techniques Tested: ${this.techniques.length}`);
    
    this.techniques.forEach((technique, index) => {
      console.log(`\nTechnique ${index + 1}:`);
      if (technique.evasions) {
        console.log(`  Evasion Methods: ${technique.evasions.length}`);
      }
      if (technique.variants) {
        console.log(`  Variants: ${technique.variants.length}`);
      }
    });
    
    console.log("=" .repeat(50));
    
    return {
      techniques: this.techniques.length,
      details: this.techniques
    };
  }
}

// Defensive Evasion Detection
class DefensiveEvasionDetection {
  static detectEncodingEvasion(payload) {
    // Check for multiple encoding layers
    const indicators = [
      /%[0-9a-fA-F]{2}/g, // URL encoding
      /[A-Za-z0-9+\/]{4}*={0,2}/, // Base64
      /\\x[0-9a-fA-F]{2}/g, // Hex encoding
      /\\u[0-9a-fA-F]{4}/g // Unicode encoding
    ];
    
    return indicators.some(pattern => pattern.test(payload));
  }

  static detectBehavioralAnomalies(behavior) {
    const anomalies = [];
    
    if (behavior.requestRate > 100) {
      anomalies.push("High request rate");
    }
    
    if (behavior.userAgents.length > 10) {
      anomalies.push("Excessive user agent rotation");
    }
    
    if (behavior.ipAddresses.length > 5) {
      anomalies.push("Multiple IP addresses");
    }
    
    return anomalies;
  }
}

// Test Scenarios
async function testSignatureEvasion() {
  console.log("\n📝 Test 1: Signature Evasion");
  
  const framework = new EvasionFramework();
  const payload = "' OR '1'='1";
  const methods = ["Encoding", "Double Encoding", "Base64 Encoding", "Hex Encoding"];
  
  const results = framework.testSignatureEvasion(payload, methods);
  expect(results).to.have.property("evasions");
  expect(results.evasions.length).to.equal(methods.length);
  console.log(`✅ Tested ${results.evasions.length} signature evasion methods`);
}

async function testBehavioralEvasion() {
  console.log("\n📝 Test 2: Behavioral Evasion");
  
  const framework = new EvasionFramework();
  const results = framework.testBehavioralEvasion("High request rate", []);
  
  expect(results).to.have.property("evasions");
  expect(results.evasions.length).to.be.greaterThan(0);
  console.log(`✅ Tested ${results.evasions.length} behavioral evasion methods`);
}

async function testEncodingTechniques() {
  console.log("\n📝 Test 3: Encoding Techniques");
  
  const framework = new EvasionFramework();
  const encodings = framework.testEncodingTechniques("test payload");
  
  expect(encodings).to.have.property("url");
  expect(encodings).to.have.property("base64");
  expect(encodings).to.have.property("hex");
  console.log(`✅ Tested ${Object.keys(encodings).length} encoding techniques`);
}

async function testPolymorphism() {
  console.log("\n📝 Test 4: Polymorphism");
  
  const framework = new EvasionFramework();
  const variants = framework.testPolymorphism("SELECT * FROM users");
  
  expect(variants).to.be.an("array");
  expect(variants.length).to.be.greaterThan(0);
  console.log(`✅ Generated ${variants.length} polymorphic variants`);
}

async function testAntiForensics() {
  console.log("\n📝 Test 5: Anti-Forensics Techniques");
  
  const framework = new EvasionFramework();
  const techniques = framework.testAntiForensics();
  
  expect(techniques).to.be.an("array");
  expect(techniques.length).to.be.greaterThan(0);
  console.log(`✅ Analyzed ${techniques.length} anti-forensics techniques`);
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test evasion techniques on systems you own or have permission to test.\n");
    
    await testSignatureEvasion();
    await testBehavioralEvasion();
    await testEncodingTechniques();
    await testPolymorphism();
    await testAntiForensics();
    
    console.log("\n✅ All evasion technique tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Monitor for encoding evasion");
    console.log("   - Detect behavioral anomalies");
    console.log("   - Use multiple detection layers");
    console.log("   - Implement behavioral analysis");
    console.log("   - Monitor for anti-forensics techniques");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();

