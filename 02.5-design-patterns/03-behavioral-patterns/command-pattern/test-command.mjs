/**
 * PHASE 2.5: DESIGN PATTERNS
 * Module 3: Behavioral Patterns
 * Lesson 3: Command Pattern
 * 
 * Learning Objectives:
 * - Understand the Command Pattern
 * - Encapsulate test operations as commands
 * - Support undo/redo operations
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== COMMAND PATTERN: TEST COMMAND ===");

// Command Interface
class Command {
  async execute() {
    throw new Error("Execute method must be implemented");
  }
  
  async undo() {
    throw new Error("Undo method must be implemented");
  }
}

// Concrete Commands
class GetRequestCommand extends Command {
  constructor(client, endpoint) {
    super();
    this.client = client;
    this.endpoint = endpoint;
    this.response = null;
  }
  
  async execute() {
    this.response = await this.client.get(this.endpoint);
    return this.response;
  }
  
  async undo() {
    // GET requests are idempotent, no undo needed
    return { message: "GET request cannot be undone" };
  }
}

class PostRequestCommand extends Command {
  constructor(client, endpoint, data) {
    super();
    this.client = client;
    this.endpoint = endpoint;
    this.data = data;
    this.response = null;
    this.createdId = null;
  }
  
  async execute() {
    this.response = await this.client.post(this.endpoint).send(this.data);
    this.createdId = this.response.body?.id;
    return this.response;
  }
  
  async undo() {
    if (this.createdId) {
      try {
        return await this.client.delete(`${this.endpoint}/${this.createdId}`);
      } catch (error) {
        return { error: "Failed to undo POST request", message: error.message };
      }
    }
    return { message: "No resource to delete" };
  }
}

class DeleteRequestCommand extends Command {
  constructor(client, endpoint, resourceId) {
    super();
    this.client = client;
    this.endpoint = endpoint;
    this.resourceId = resourceId;
    this.deletedData = null;
  }
  
  async execute() {
    // Store data before deletion for undo
    const getResponse = await this.client.get(`${this.endpoint}/${this.resourceId}`);
    this.deletedData = getResponse.body;
    
    const response = await this.client.delete(`${this.endpoint}/${this.resourceId}`);
    return response;
  }
  
  async undo() {
    if (this.deletedData) {
      try {
        return await this.client.post(this.endpoint).send(this.deletedData);
      } catch (error) {
        return { error: "Failed to undo DELETE request", message: error.message };
      }
    }
    return { message: "No data to restore" };
  }
}

// Invoker
class CommandInvoker {
  constructor() {
    this.history = [];
    this.undoStack = [];
  }
  
  async executeCommand(command) {
    const result = await command.execute();
    this.history.push({ command, result, timestamp: Date.now() });
    return result;
  }
  
  async undo() {
    if (this.history.length === 0) {
      return { message: "No commands to undo" };
    }
    
    const lastCommand = this.history.pop();
    const undoResult = await lastCommand.command.undo();
    this.undoStack.push({ command: lastCommand.command, result: undoResult });
    return undoResult;
  }
  
  async redo() {
    if (this.undoStack.length === 0) {
      return { message: "No commands to redo" };
    }
    
    const lastUndo = this.undoStack.pop();
    const result = await lastUndo.command.execute();
    this.history.push({ command: lastUndo.command, result, timestamp: Date.now() });
    return result;
  }
  
  getHistory() {
    return this.history;
  }
}

// Exercises and Tests
describe("Command Pattern - Test Command", () => {
  const baseURL = "https://jsonplaceholder.typicode.com";
  const client = supertest(baseURL);
  
  it("should execute GET command", async () => {
    const command = new GetRequestCommand(client, "/posts/1");
    const invoker = new CommandInvoker();
    
    const result = await invoker.executeCommand(command);
    
    expect(result.status).to.equal(200);
    expect(result.body).to.have.property('id');
  });

  it("should execute POST command", async () => {
    const data = { title: "Test", body: "Test body", userId: 1 };
    const command = new PostRequestCommand(client, "/posts", data);
    const invoker = new CommandInvoker();
    
    const result = await invoker.executeCommand(command);
    
    expect(result.status).to.equal(201);
    expect(result.body).to.have.property('id');
  });

  it("should undo POST command", async () => {
    const data = { title: "Test", body: "Test body", userId: 1 };
    const command = new PostRequestCommand(client, "/posts", data);
    const invoker = new CommandInvoker();
    
    await invoker.executeCommand(command);
    const undoResult = await invoker.undo();
    
    expect(undoResult.status).to.be.oneOf([200, 204]);
  });

  it("should maintain command history", async () => {
    const invoker = new CommandInvoker();
    
    const command1 = new GetRequestCommand(client, "/posts/1");
    const command2 = new GetRequestCommand(client, "/posts/2");
    
    await invoker.executeCommand(command1);
    await invoker.executeCommand(command2);
    
    const history = invoker.getHistory();
    expect(history.length).to.equal(2);
  });

  it("should support redo operation", async () => {
    const invoker = new CommandInvoker();
    const command = new GetRequestCommand(client, "/posts/1");
    
    await invoker.executeCommand(command);
    await invoker.undo();
    const redoResult = await invoker.redo();
    
    expect(redoResult.status).to.equal(200);
  });
});

// Export classes
export { 
  Command, 
  GetRequestCommand, 
  PostRequestCommand, 
  DeleteRequestCommand,
  CommandInvoker 
};

