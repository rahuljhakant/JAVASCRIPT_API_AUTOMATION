/**
 * Environment Loader Utility
 * Provides utilities for loading and managing environment variables
 */

import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Load environment variables
dotenv.config();

/**
 * Get API token from environment variables
 * @returns {string} API token
 */
export function getApiToken() {
  const token = process.env.API_TOKEN || process.env.GOREST_API_TOKEN || process.env.BEARER_TOKEN;
  
  if (!token) {
    console.warn('⚠️  Warning: API token not found in environment variables');
    console.warn('Please set API_TOKEN, GOREST_API_TOKEN, or BEARER_TOKEN in your .env file');
    return 'your-token-here'; // Placeholder for tutorial purposes
  }
  
  return token;
}

/**
 * Get API base URL from environment variables
 * @param {string} defaultUrl - Default URL if not found in env
 * @returns {string} API base URL
 */
export function getApiBaseUrl(defaultUrl = 'https://gorest.co.in/public-api/') {
  return process.env.API_BASE_URL || process.env.BASE_URL || defaultUrl;
}

/**
 * Get environment name
 * @returns {string} Environment name (development, staging, production, testing)
 */
export function getEnvironment() {
  return process.env.NODE_ENV || process.env.ENVIRONMENT || 'development';
}

/**
 * Get configuration for a specific environment
 * @param {string} env - Environment name
 * @returns {object} Environment configuration
 */
export async function getEnvironmentConfig(env = null) {
  const environment = env || getEnvironment();
  
  try {
    const configPath = join(dirname(fileURLToPath(import.meta.url)), '../config/environments', `${environment}.json`);
    const config = await import(configPath, { assert: { type: 'json' } });
    return config.default || config;
  } catch (error) {
    console.warn(`Configuration file for ${environment} not found, using defaults`);
    return {
      apiUrl: getApiBaseUrl(),
      timeout: 30000,
      retries: 3
    };
  }
}

/**
 * Check if running in production
 * @returns {boolean}
 */
export function isProduction() {
  return getEnvironment() === 'production';
}

/**
 * Check if running in development
 * @returns {boolean}
 */
export function isDevelopment() {
  return getEnvironment() === 'development';
}

export default {
  getApiToken,
  getApiBaseUrl,
  getEnvironment,
  getEnvironmentConfig,
  isProduction,
  isDevelopment
};

