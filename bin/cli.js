#!/usr/bin/env node

import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

// Get the directory of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path to the main index.js file
const indexPath = path.join(__dirname, '..', 'index.js');

// Check for debug flag
const debugMode = process.argv.includes('--debug');

// Set environment variables
if (debugMode) {
  process.env.DEBUG = 'true';
}

// Run the main application
console.log('Starting OpenSearch MCP Server...');
if (debugMode) console.log('Debug mode enabled');

// Execute the main index.js file
const result = spawnSync('node', [indexPath], { 
  stdio: 'inherit',
  env: process.env
});

// Handle exit
process.exit(result.status);