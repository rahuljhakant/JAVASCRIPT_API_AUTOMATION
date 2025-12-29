/**
 * PHASE 1: BEGINNER LEVEL
 * Module 3: GET Operations
 * Lesson 2: Pagination Handling
 * 
 * Learning Objectives:
 * - Understand pagination concepts
 * - Handle page-based pagination
 * - Work with offset/limit pagination
 * - Navigate through multiple pages
 */

import { expect } from "chai";
import supertest from "supertest";

console.log("=== PAGINATION HANDLING ===");

// Set up the API client
const request = supertest("https://jsonplaceholder.typicode.com");

// Page-based pagination
async function getPage(pageNumber, pageSize = 10) {
  console.log(`Fetching page ${pageNumber} with size ${pageSize}...`);
  
  const response = await request
    .get("/posts")
    .query({
      _page: pageNumber,
      _limit: pageSize
    });
  
  return response;
}

// Offset/limit pagination
async function getWithOffset(offset, limit = 10) {
  console.log(`Fetching from offset ${offset} with limit ${limit}...`);
  
  const response = await request
    .get("/posts")
    .query({
      _start: offset,
      _limit: limit
    });
  
  return response;
}

// Get all pages
async function getAllPages(pageSize = 10) {
  let allPosts = [];
  let page = 1;
  let hasMore = true;
  
  while (hasMore) {
    const response = await getPage(page, pageSize);
    allPosts = allPosts.concat(response.body);
    
    if (response.body.length < pageSize) {
      hasMore = false;
    } else {
      page++;
    }
  }
  
  return allPosts;
}

// Exercises and Tests
describe("Pagination Handling", () => {
  it("should fetch first page of results", async () => {
    const response = await getPage(1, 10);
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    expect(response.body.length).to.be.at.most(10);
  });

  it("should fetch second page of results", async () => {
    const response = await getPage(2, 10);
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
    
    // Verify it's different from first page
    if (response.body.length > 0) {
      const firstPage = await getPage(1, 10);
      expect(response.body[0].id).to.not.equal(firstPage.body[0].id);
    }
  });

  it("should handle custom page size", async () => {
    const pageSize = 5;
    const response = await getPage(1, pageSize);
    
    expect(response.status).to.equal(200);
    expect(response.body.length).to.be.at.most(pageSize);
  });

  it("should fetch results with offset and limit", async () => {
    const offset = 10;
    const limit = 5;
    const response = await getWithOffset(offset, limit);
    
    expect(response.status).to.equal(200);
    expect(response.body.length).to.be.at.most(limit);
  });

  it("should handle empty page gracefully", async () => {
    const response = await getPage(9999, 10);
    
    expect(response.status).to.equal(200);
    expect(response.body).to.be.an('array');
  });
});

// Advanced Pagination Examples
describe("Advanced Pagination", () => {
  it("should navigate through multiple pages", async () => {
    const pages = [1, 2, 3];
    const results = [];
    
    for (const page of pages) {
      const response = await getPage(page, 10);
      results.push(response.body);
    }
    
    expect(results).to.have.length(3);
    results.forEach(pageResults => {
      expect(pageResults).to.be.an('array');
    });
  });

  it("should fetch all pages sequentially", async () => {
    const allPosts = await getAllPages(10);
    
    expect(allPosts).to.be.an('array');
    expect(allPosts.length).to.be.greaterThan(0);
    
    // Verify no duplicates
    const ids = allPosts.map(post => post.id);
    const uniqueIds = [...new Set(ids)];
    expect(uniqueIds.length).to.equal(ids.length);
  });

  it("should handle pagination with filters", async () => {
    const response = await request
      .get("/posts")
      .query({
        userId: 1,
        _page: 1,
        _limit: 5
      });
    
    expect(response.status).to.equal(200);
    expect(response.body.length).to.be.at.most(5);
    
    response.body.forEach(post => {
      expect(post.userId).to.equal(1);
    });
  });
});

// Pagination Utilities
class PaginationHelper {
  static async fetchAllPages(apiClient, endpoint, pageSize = 10, filters = {}) {
    let allResults = [];
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      const response = await apiClient
        .get(endpoint)
        .query({
          ...filters,
          _page: page,
          _limit: pageSize
        });
      
      allResults = allResults.concat(response.body);
      
      if (response.body.length < pageSize) {
        hasMore = false;
      } else {
        page++;
      }
    }
    
    return allResults;
  }
  
  static calculateTotalPages(totalItems, pageSize) {
    return Math.ceil(totalItems / pageSize);
  }
}

// Export functions and classes
export { 
  getPage, 
  getWithOffset, 
  getAllPages,
  PaginationHelper 
};

