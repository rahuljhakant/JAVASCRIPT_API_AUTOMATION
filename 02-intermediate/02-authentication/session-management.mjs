/**
 * PHASE 2: INTERMEDIATE LEVEL
 * Module 2: Authentication
 * Lesson 3: Session Management
 * 
 * Learning Objectives:
 * - Understand session-based authentication
 * - Implement session creation and management
 * - Handle session cookies and tokens
 * - Manage session expiration and renewal
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== SESSION MANAGEMENT ===");

// API client setup - using httpbin.org for session simulation
const request = supertest("https://httpbin.org");

// Session Manager
class SessionManager {
  constructor() {
    this.sessions = new Map();
    this.cookies = new Map();
  }
  
  createSession(userId, metadata = {}) {
    const sessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const session = {
      id: sessionId,
      userId,
      createdAt: new Date(),
      lastAccessed: new Date(),
      expiresAt: new Date(Date.now() + 3600000), // 1 hour default
      metadata,
      active: true
    };
    
    this.sessions.set(sessionId, session);
    return session;
  }
  
  getSession(sessionId) {
    const session = this.sessions.get(sessionId);
    
    if (session && session.active) {
      if (new Date() > session.expiresAt) {
        this.invalidateSession(sessionId);
        return null;
      }
      
      session.lastAccessed = new Date();
      return session;
    }
    
    return null;
  }
  
  invalidateSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.active = false;
      this.sessions.delete(sessionId);
      return true;
    }
    return false;
  }
  
  renewSession(sessionId, extensionMinutes = 60) {
    const session = this.sessions.get(sessionId);
    if (session && session.active) {
      session.expiresAt = new Date(Date.now() + extensionMinutes * 60000);
      session.lastAccessed = new Date();
      return true;
    }
    return false;
  }
  
  getAllSessions() {
    return Array.from(this.sessions.values()).filter(s => s.active);
  }
  
  cleanupExpiredSessions() {
    const now = new Date();
    let cleaned = 0;
    
    for (const [sessionId, session] of this.sessions.entries()) {
      if (now > session.expiresAt) {
        this.invalidateSession(sessionId);
        cleaned++;
      }
    }
    
    return cleaned;
  }
}

// Session Authentication Service
class SessionAuthService {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.sessionManager = new SessionManager();
  }
  
  async login(username, password) {
    // Simulate login - in real scenario, this would call actual login endpoint
    const response = await this.apiClient
      .post("/post")
      .send({ username, password });
    
    if (response.status === 200) {
      // Create session
      const session = this.sessionManager.createSession(username);
      
      // Extract cookies from response
      const cookies = this.extractCookies(response);
      
      return {
        success: true,
        session,
        cookies,
        response
      };
    }
    
    return {
      success: false,
      response
    };
  }
  
  async requestWithSession(sessionId, endpoint = "/get") {
    const session = this.sessionManager.getSession(sessionId);
    
    if (!session) {
      throw new Error("Invalid or expired session");
    }
    
    // In real scenario, you would send session cookie or token
    const response = await this.apiClient
      .get(endpoint)
      .set("Cookie", `sessionId=${sessionId}`);
    
    return response;
  }
  
  async logout(sessionId) {
    const invalidated = this.sessionManager.invalidateSession(sessionId);
    
    // In real scenario, call logout endpoint
    const response = await this.apiClient
      .post("/post")
      .send({ action: "logout", sessionId });
    
    return {
      invalidated,
      response
    };
  }
  
  extractCookies(response) {
    const cookies = {};
    const setCookieHeader = response.headers['set-cookie'];
    
    if (setCookieHeader) {
      if (Array.isArray(setCookieHeader)) {
        setCookieHeader.forEach(cookie => {
          const [nameValue] = cookie.split(';');
          const [name, value] = nameValue.split('=');
          cookies[name] = value;
        });
      } else {
        const [nameValue] = setCookieHeader.split(';');
        const [name, value] = nameValue.split('=');
        cookies[name] = value;
      }
    }
    
    return cookies;
  }
  
  async refreshSession(sessionId) {
    const renewed = this.sessionManager.renewSession(sessionId);
    
    if (renewed) {
      // In real scenario, call refresh endpoint
      const response = await this.apiClient
        .post("/post")
        .send({ action: "refresh", sessionId });
      
      return {
        success: true,
        session: this.sessionManager.getSession(sessionId),
        response
      };
    }
    
    return {
      success: false,
      error: "Session not found or expired"
    };
  }
}

// Cookie Manager
class CookieManager {
  constructor() {
    this.cookies = new Map();
  }
  
  setCookie(name, value, options = {}) {
    this.cookies.set(name, {
      value,
      domain: options.domain,
      path: options.path || '/',
      expires: options.expires,
      secure: options.secure || false,
      httpOnly: options.httpOnly || false,
      sameSite: options.sameSite || 'Lax'
    });
  }
  
  getCookie(name) {
    const cookie = this.cookies.get(name);
    if (cookie) {
      // Check expiration
      if (cookie.expires && new Date() > cookie.expires) {
        this.cookies.delete(name);
        return null;
      }
      return cookie.value;
    }
    return null;
  }
  
  deleteCookie(name) {
    return this.cookies.delete(name);
  }
  
  getAllCookies() {
    return Array.from(this.cookies.entries()).map(([name, data]) => ({
      name,
      value: data.value,
      ...data
    }));
  }
  
  buildCookieHeader() {
    const cookieStrings = Array.from(this.cookies.entries()).map(([name, data]) => {
      return `${name}=${data.value}`;
    });
    
    return cookieStrings.join('; ');
  }
}

// Exercises and Tests
describe("Session Management", () => {
  let sessionManager;
  let authService;
  
  beforeEach(() => {
    sessionManager = new SessionManager();
    authService = new SessionAuthService(request);
  });
  
  it("should create a new session", () => {
    const session = sessionManager.createSession("user123");
    
    expect(session).to.exist;
    expect(session.id).to.be.a('string');
    expect(session.userId).to.equal("user123");
    expect(session.active).to.be.true;
    expect(session.expiresAt).to.be.instanceOf(Date);
    
    console.log("Session created:", session.id);
  });
  
  it("should retrieve an active session", () => {
    const session = sessionManager.createSession("user123");
    const retrieved = sessionManager.getSession(session.id);
    
    expect(retrieved).to.exist;
    expect(retrieved.id).to.equal(session.id);
    expect(retrieved.userId).to.equal("user123");
  });
  
  it("should invalidate a session", () => {
    const session = sessionManager.createSession("user123");
    const invalidated = sessionManager.invalidateSession(session.id);
    
    expect(invalidated).to.be.true;
    
    const retrieved = sessionManager.getSession(session.id);
    expect(retrieved).to.be.null;
  });
  
  it("should handle expired sessions", () => {
    const session = sessionManager.createSession("user123");
    // Manually expire the session
    session.expiresAt = new Date(Date.now() - 1000);
    
    const retrieved = sessionManager.getSession(session.id);
    expect(retrieved).to.be.null;
  });
  
  it("should renew a session", () => {
    const session = sessionManager.createSession("user123");
    const originalExpiry = session.expiresAt;
    
    // Wait a bit
    setTimeout(() => {
      const renewed = sessionManager.renewSession(session.id, 60);
      expect(renewed).to.be.true;
      
      const updatedSession = sessionManager.getSession(session.id);
      expect(updatedSession.expiresAt.getTime()).to.be.greaterThan(originalExpiry.getTime());
    }, 100);
  });
  
  it("should cleanup expired sessions", () => {
    // Create multiple sessions
    const session1 = sessionManager.createSession("user1");
    const session2 = sessionManager.createSession("user2");
    const session3 = sessionManager.createSession("user3");
    
    // Expire one session
    session2.expiresAt = new Date(Date.now() - 1000);
    
    const cleaned = sessionManager.cleanupExpiredSessions();
    expect(cleaned).to.be.greaterThan(0);
    
    const activeSessions = sessionManager.getAllSessions();
    expect(activeSessions.length).to.be.lessThan(3);
  });
  
  it("should simulate login and session creation", async () => {
    const loginResult = await authService.login("testuser", "testpass");
    
    expect(loginResult).to.exist;
    expect(loginResult.session).to.exist;
    expect(loginResult.session.id).to.be.a('string');
    expect(loginResult.session.active).to.be.true;
    
    console.log("Login successful, session created:", loginResult.session.id);
  });
  
  it("should make authenticated requests with session", async () => {
    const loginResult = await authService.login("testuser", "testpass");
    const sessionId = loginResult.session.id;
    
    const response = await authService.requestWithSession(sessionId);
    
    expect(response.status).to.equal(200);
    console.log("Authenticated request successful");
  });
  
  it("should handle logout", async () => {
    const loginResult = await authService.login("testuser", "testpass");
    const sessionId = loginResult.session.id;
    
    const logoutResult = await authService.logout(sessionId);
    
    expect(logoutResult.invalidated).to.be.true;
    
    // Try to use session after logout
    try {
      await authService.requestWithSession(sessionId);
      expect.fail("Should have thrown error for invalid session");
    } catch (error) {
      expect(error.message).to.include("Invalid or expired session");
    }
  });
  
  it("should refresh an active session", async () => {
    const loginResult = await authService.login("testuser", "testpass");
    const sessionId = loginResult.session.id;
    
    const refreshResult = await authService.refreshSession(sessionId);
    
    expect(refreshResult.success).to.be.true;
    expect(refreshResult.session).to.exist;
    expect(refreshResult.session.expiresAt.getTime()).to.be.greaterThan(Date.now());
    
    console.log("Session refreshed successfully");
  });
});

// Cookie Management
describe("Cookie Management", () => {
  let cookieManager;
  
  beforeEach(() => {
    cookieManager = new CookieManager();
  });
  
  it("should set and get cookies", () => {
    cookieManager.setCookie("sessionId", "abc123");
    
    const value = cookieManager.getCookie("sessionId");
    expect(value).to.equal("abc123");
  });
  
  it("should handle cookie expiration", () => {
    const expires = new Date(Date.now() + 1000); // Expires in 1 second
    cookieManager.setCookie("temp", "value", { expires });
    
    const value1 = cookieManager.getCookie("temp");
    expect(value1).to.equal("value");
    
    // Wait for expiration
    setTimeout(() => {
      const value2 = cookieManager.getCookie("temp");
      expect(value2).to.be.null;
    }, 1100);
  });
  
  it("should delete cookies", () => {
    cookieManager.setCookie("test", "value");
    expect(cookieManager.getCookie("test")).to.equal("value");
    
    cookieManager.deleteCookie("test");
    expect(cookieManager.getCookie("test")).to.be.null;
  });
  
  it("should build cookie header string", () => {
    cookieManager.setCookie("sessionId", "abc123");
    cookieManager.setCookie("userId", "user456");
    
    const header = cookieManager.buildCookieHeader();
    expect(header).to.include("sessionId=abc123");
    expect(header).to.include("userId=user456");
  });
  
  it("should handle secure cookies", () => {
    cookieManager.setCookie("secure", "value", { secure: true });
    const cookie = cookieManager.getAllCookies().find(c => c.name === "secure");
    
    expect(cookie.secure).to.be.true;
  });
  
  it("should handle httpOnly cookies", () => {
    cookieManager.setCookie("httpOnly", "value", { httpOnly: true });
    const cookie = cookieManager.getAllCookies().find(c => c.name === "httpOnly");
    
    expect(cookie.httpOnly).to.be.true;
  });
});

// Advanced Session Operations
describe("Advanced Session Operations", () => {
  let sessionManager;
  let authService;
  
  beforeEach(() => {
    sessionManager = new SessionManager();
    authService = new SessionAuthService(request);
  });
  
  it("should handle concurrent session access", async () => {
    const loginResult = await authService.login("testuser", "testpass");
    const sessionId = loginResult.session.id;
    
    // Make multiple concurrent requests
    const requests = Array.from({ length: 5 }, () =>
      authService.requestWithSession(sessionId)
    );
    
    const responses = await Promise.all(requests);
    
    responses.forEach(response => {
      expect(response.status).to.equal(200);
    });
    
    console.log("Concurrent session access successful");
  });
  
  it("should track session last accessed time", () => {
    const session = sessionManager.createSession("user123");
    const firstAccess = session.lastAccessed;
    
    // Wait a bit
    setTimeout(() => {
      sessionManager.getSession(session.id);
      const secondAccess = session.lastAccessed;
      
      expect(secondAccess.getTime()).to.be.greaterThan(firstAccess.getTime());
    }, 100);
  });
  
  it("should handle session metadata", () => {
    const metadata = {
      ipAddress: "192.168.1.1",
      userAgent: "Mozilla/5.0",
      loginMethod: "password"
    };
    
    const session = sessionManager.createSession("user123", metadata);
    
    expect(session.metadata).to.deep.equal(metadata);
    expect(session.metadata.ipAddress).to.equal("192.168.1.1");
  });
  
  it("should implement session timeout", () => {
    const session = sessionManager.createSession("user123");
    // Set short timeout (1 second)
    session.expiresAt = new Date(Date.now() + 1000);
    
    // Access immediately
    const session1 = sessionManager.getSession(session.id);
    expect(session1).to.exist;
    
    // Access after timeout
    setTimeout(() => {
      const session2 = sessionManager.getSession(session.id);
      expect(session2).to.be.null;
    }, 1100);
  });
  
  it("should handle session hijacking prevention", () => {
    const session = sessionManager.createSession("user123", {
      ipAddress: "192.168.1.1",
      userAgent: "Mozilla/5.0"
    });
    
    // Verify session matches request context
    const verifySession = (sessionId, ipAddress, userAgent) => {
      const session = sessionManager.getSession(sessionId);
      if (!session) return false;
      
      return session.metadata.ipAddress === ipAddress &&
             session.metadata.userAgent === userAgent;
    };
    
    const valid = verifySession(session.id, "192.168.1.1", "Mozilla/5.0");
    const invalid = verifySession(session.id, "192.168.1.2", "Mozilla/5.0");
    
    expect(valid).to.be.true;
    expect(invalid).to.be.false;
  });
});

export { 
  SessionManager, 
  SessionAuthService, 
  CookieManager 
};

