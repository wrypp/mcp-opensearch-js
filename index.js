// OpenSearch MCP Server
import { FastMCP, UserError, imageContent } from "fastmcp";
import { Client } from "@opensearch-project/opensearch";
import { z } from "zod";
import dotenv from 'dotenv';
import util from 'util';

// Load environment variables
dotenv.config();

// Configure debug logging
const DEBUG = process.env.DEBUG === 'true' || process.env.DEBUG === '1';
function debugLog(...args) {
  if (DEBUG) {
    const timestamp = new Date().toISOString();
    const formattedArgs = args.map(arg => 
      typeof arg === 'object' ? util.inspect(arg, { depth: 3, colors: true }) : arg
    );
    console.error(`[${timestamp}] [DEBUG]`, ...formattedArgs);
  }
}

console.log('Starting OpenSearch MCP Server (stdio mode)');
debugLog('Debug logging enabled');

// Configure OpenSearch client with increased timeout
const client = new Client({
  // Get connection details from environment variables
  node: process.env.OPENSEARCH_URL || "https://localhost:9200",
  auth: {
    username: process.env.OPENSEARCH_USERNAME || "admin",
    password: process.env.OPENSEARCH_PASSWORD || "admin",
  },
  ssl: {
    rejectUnauthorized: false, // Set to true in production with proper certificates
  },
  // Add increased timeouts to avoid MCP timeout errors
  requestTimeout: 30000, // 30 seconds for API requests
  connectionTimeout: 10000, // 10 seconds for initial connection
  maxRetries: 3, // Allow retries on failure
});

debugLog('OpenSearch client configured with:', {
  node: process.env.OPENSEARCH_URL || "https://localhost:9200",
  requestTimeout: 30000,
  connectionTimeout: 10000,
  maxRetries: 3
});

// Initialize MCP Server with increased timeout
const server = new FastMCP({
  name: "OpenSearch Security Analytics",
  version: "1.0.0",
  description: "MCP server for querying Wazuh security logs in OpenSearch",
  // Increase the default MCP execution timeout
  defaultExecutionTimeoutMs: 120000, // 2 minutes
});

debugLog('MCP Server initialized with timeout:', 120000);

// Helper function to safely execute OpenSearch queries
async function safeOpenSearchQuery(operation, fallbackMessage) {
  try {
    debugLog('Executing OpenSearch query');
    const result = await operation();
    debugLog('OpenSearch query completed successfully');
    return result;
  } catch (error) {
    console.error(`OpenSearch error: ${error.message}`, error);
    debugLog('OpenSearch query failed:', error);
    
    // Check for common OpenSearch errors
    if (error.message.includes('timeout')) {
      throw new UserError(`OpenSearch request timed out. The query may be too complex or the cluster is under heavy load.`);
    } else if (error.message.includes('connect')) {
      throw new UserError(`Cannot connect to OpenSearch. Please check your connection settings in .env file.`);
    } else if (error.message.includes('no such index')) {
      throw new UserError(`The specified index doesn't exist in OpenSearch.`);
    } else if (error.message.includes('unauthorized')) {
      throw new UserError(`Authentication failed with OpenSearch. Please check your credentials in .env file.`);
    }
    
    // For any other errors
    throw new UserError(fallbackMessage || `OpenSearch operation failed: ${error.message}`);
  }
}

// Tool to list all available indexes
server.addTool({
  name: "listIndexes",
  description: "List all available indexes in OpenSearch",
  parameters: z.object({
    pattern: z.string().default("*").describe("Index pattern to filter (e.g., 'logs-*')"),
  }),
  execute: async (args, { log }) => {
    log.info("Listing indexes", { pattern: args.pattern });

    return safeOpenSearchQuery(async () => {
      const response = await client.cat.indices({
        format: "json",
        index: args.pattern,
        // Add timeout parameter to OpenSearch request
        timeout: "30s",
      });

      const indexes = response.body;
      
      if (!indexes || indexes.length === 0) {
        return "No indexes found matching your pattern.";
      }

      // Sort indexes by size (descending)
      indexes.sort((a, b) => {
        // Handle missing or undefined values
        const sizeA = a.pri?.store?.size ? parseInt(a.pri.store.size) : 0;
        const sizeB = b.pri?.store?.size ? parseInt(b.pri.store.size) : 0;
        return sizeB - sizeA;
      });

      let resultText = `## Available Indexes (${indexes.length} total)\n\n`;
      resultText += "| Index | Docs Count | Size | Status | Health |\n";
      resultText += "|-------|------------|------|--------|--------|\n";
      
      indexes.forEach(idx => {
        // Safely handle potentially missing fields
        const docsCount = idx.docs?.count || 'N/A';
        const size = idx.pri?.store?.size || 'N/A';
        const status = idx.status || 'N/A';
        const health = idx.health || 'N/A';
        
        resultText += `| ${idx.index} | ${docsCount} | ${size} | ${status} | ${health} |\n`;
      });

      return resultText;
    }, "Failed to list OpenSearch indexes. Please check your connection and try again.");
  },
});

// Tool to search any logs
server.addTool({
  name: "searchLogs",
  description: "Search for logs in any OpenSearch index",
  parameters: z.object({
    query: z.string().describe("The search query text"),
    index: z.string().describe("Index pattern to search"),
    timeField: z.string().default("@timestamp").describe("Name of the timestamp field"),
    timeRange: z.string().default("24h").describe("Time range (e.g., 1h, 24h, 7d)"),
    maxResults: z.number().default(20).describe("Maximum number of results to return"),
    fields: z.string().optional().describe("Comma-separated list of fields to return"),
  }),
  execute: async (args, { log }) => {
    log.info("Searching logs", { 
      query: args.query, 
      index: args.index,
      timeRange: args.timeRange 
    });

    return safeOpenSearchQuery(async () => {
      const timeRangeMs = parseTimeRange(args.timeRange);
      const now = new Date();
      const from = new Date(now.getTime() - timeRangeMs);

      // Build the query body
      const queryBody = {
        size: args.maxResults,
        query: {
          bool: {
            must: [
              { query_string: { query: args.query } }
            ]
          }
        },
        sort: [{ [args.timeField]: { order: "desc" } }],
        // Add timeout parameter directly in the query
        timeout: "25s"
      };

      // Add time range if timeField is specified
      if (args.timeField) {
        queryBody.query.bool.must.push({
          range: {
            [args.timeField]: {
              gte: from.toISOString(),
              lte: now.toISOString(),
            },
          },
        });
      }

      // Add source filtering if fields are specified
      if (args.fields) {
        const fieldList = args.fields.split(',').map(f => f.trim());
        queryBody._source = fieldList;
      }

      const response = await client.search({
        index: args.index,
        body: queryBody
      });

      const hits = response.body.hits.hits || [];
      const total = response.body.hits.total?.value || 0;

      log.info(`Found ${total} matching logs`, { count: total });

      if (hits.length === 0) {
        return "No logs found matching your criteria.";
      }

      let resultText = `Found ${total} logs matching your criteria. Showing top ${hits.length}:\n\n`;
      
      // Display results in a readable format
      hits.forEach((hit, i) => {
        const source = hit._source;
        resultText += `### Log ${i+1} (${hit._index})\n`;
        resultText += `- **ID**: ${hit._id}\n`;
        
        // Display timestamp if it exists
        if (source[args.timeField]) {
          resultText += `- **Time**: ${source[args.timeField]}\n`;
        }
        
        // Display top-level fields for a summary
        const topFields = Object.keys(source)
          .filter(key => 
            typeof source[key] !== 'object' && 
            key !== args.timeField
          )
          .slice(0, 5);
        
        topFields.forEach(field => {
          resultText += `- **${field}**: ${source[field]}\n`;
        });
        
        resultText += `\n\`\`\`json\n${JSON.stringify(source, null, 2)}\n\`\`\`\n\n`;
      });

      return resultText;
    }, "Failed to search logs. Please check your query and connection settings.");
  },
});

// Tool to get index mappings
server.addTool({
  name: "getIndexMapping",
  description: "Get the field mappings for an index",
  parameters: z.object({
    index: z.string().describe("Index name to inspect"),
  }),
  execute: async (args, { log }) => {
    log.info("Getting index mapping", { index: args.index });

    return safeOpenSearchQuery(async () => {
      const response = await client.indices.getMapping({
        index: args.index,
        timeout: "20s"
      });

      const mappings = response.body;
      if (!mappings) {
        return `No mappings found for index ${args.index}.`;
      }
      
      const indexName = Object.keys(mappings)[0];
      const properties = mappings[indexName]?.mappings?.properties || {};
      
      if (Object.keys(properties).length === 0) {
        return `No field mappings found for index ${args.index}.`;
      }

      let resultText = `## Field Mappings for ${args.index}\n\n`;
      
      function processProperties(props, prefix = '') {
        Object.entries(props).forEach(([field, details]) => {
          const fullPath = prefix ? `${prefix}.${field}` : field;
          
          if (details.type) {
            resultText += `- **${fullPath}**: ${details.type}`;
            if (details.fields) {
              resultText += ` (has multi-fields)`;
            }
            resultText += '\n';
          }
          
          // Recursively process nested fields
          if (details.properties) {
            processProperties(details.properties, fullPath);
          }
          
          // Process multi-fields
          if (details.fields) {
            Object.entries(details.fields).forEach(([subField, subDetails]) => {
              resultText += `  - ${fullPath}.${subField}: ${subDetails.type}\n`;
            });
          }
        });
      }
      
      processProperties(properties);
      
      return resultText;
    }, `Failed to get mapping for index ${args.index}.`);
  },
});

// Tool to explore field values
server.addTool({
  name: "exploreFieldValues",
  description: "Explore possible values for a field in an index",
  parameters: z.object({
    index: z.string().describe("Index pattern to search"),
    field: z.string().describe("Field name to explore"),
    query: z.string().default("*").describe("Optional query to filter documents"),
    maxValues: z.number().default(20).describe("Maximum number of values to return"),
  }),
  execute: async (args, { log }) => {
    log.info("Exploring field values", { 
      index: args.index,
      field: args.field,
      query: args.query 
    });

    return safeOpenSearchQuery(async () => {
      const response = await client.search({
        index: args.index,
        body: {
          size: 0,
          query: {
            query_string: {
              query: args.query
            }
          },
          aggs: {
            field_values: {
              terms: {
                field: args.field,
                size: args.maxValues
              }
            }
          },
          timeout: "25s"
        }
      });

      const buckets = response.body.aggregations?.field_values?.buckets || [];
      const total = response.body.hits.total?.value || 0;
      
      if (buckets.length === 0) {
        return `No values found for field "${args.field}" in index ${args.index}.\n\nPossible reasons:\n- The field does not exist\n- The field is not indexed for aggregations\n- No documents match your query\n- The field has no values`;
      }

      let resultText = `## Values for field "${args.field}" in ${args.index}\n\n`;
      resultText += `Found ${total} matching documents. Top ${buckets.length} values:\n\n`;
      
      // Calculate percentage of total for each value
      let totalCount = buckets.reduce((sum, bucket) => sum + bucket.doc_count, 0);
      
      // Format results as a table
      resultText += "| Value | Count | Percentage |\n";
      resultText += "|-------|-------|------------|\n";
      
      buckets.forEach(bucket => {
        const percentage = ((bucket.doc_count / totalCount) * 100).toFixed(2);
        resultText += `| ${bucket.key} | ${bucket.doc_count} | ${percentage}% |\n`;
      });
      
      return resultText;
    }, `Failed to explore values for field "${args.field}" in index ${args.index}.`);
  },
});

// Tool to monitor logs in real-time
server.addTool({
  name: "monitorLogs",
  description: "Monitor logs in real-time (simulated)",
  parameters: z.object({
    index: z.string().describe("Index pattern to monitor"),
    query: z.string().default("*").describe("Filter query"),
    refreshInterval: z.number().default(5).describe("Refresh interval in seconds"),
    maxResults: z.number().default(10).describe("Number of logs to show"),
  }),
  execute: async (args, { log, reportProgress }) => {
    log.info("Monitoring logs", { 
      index: args.index,
      query: args.query,
      interval: args.refreshInterval
    });

    // This is a simulated implementation since real-time monitoring
    // would require a persistent connection
    reportProgress({
      progress: 10,
      total: 100,
      message: "Preparing log monitoring..."
    });

    return safeOpenSearchQuery(async () => {
      // Get an initial set of logs
      const response = await client.search({
        index: args.index,
        body: {
          size: args.maxResults,
          query: {
            query_string: {
              query: args.query
            }
          },
          sort: [
            { "@timestamp": { order: "desc" } }
          ],
          timeout: "20s"
        }
      });

      const hits = response.body.hits.hits || [];
      reportProgress({
        progress: 100,
        total: 100,
        message: "Log monitoring ready"
      });

      if (hits.length === 0) {
        return "No logs found matching your criteria.";
      }

      let resultText = `## Log Monitor for ${args.index}\n\n`;
      resultText += `Query: ${args.query}\n\n`;
      resultText += `To implement real-time monitoring, you would need to:\n`;
      resultText += `1. Set up an interval to poll for new logs every ${args.refreshInterval} seconds\n`;
      resultText += `2. Track the timestamp of the most recent log\n`;
      resultText += `3. Query only for logs newer than that timestamp\n\n`;
      
      resultText += `### Most Recent Logs\n\n`;
      
      // Display results in a readable format
      hits.forEach((hit, i) => {
        const source = hit._source;
        // Safely access timestamp fields
        const timestamp = source['@timestamp'] || source.timestamp;
        const timeDisplay = timestamp ? new Date(timestamp).toLocaleString() : 'Unknown time';
        
        resultText += `**Log ${i+1}** (${timeDisplay}):\n`;
        
        // Show a summary with key fields
        const importantFields = ['message', 'level', 'logger_name', 'status', 'method', 'path'];
        let foundFields = false;
        
        importantFields.forEach(field => {
          if (source[field]) {
            resultText += `- **${field}**: ${source[field]}\n`;
            foundFields = true;
          }
        });
        
        // If none of the important fields were found, show the first few fields
        if (!foundFields) {
          Object.entries(source)
            .filter(([key]) => typeof source[key] !== 'object' && key !== '@timestamp' && key !== 'timestamp')
            .slice(0, 3)
            .forEach(([key, value]) => {
              resultText += `- **${key}**: ${value}\n`;
            });
        }
        
        resultText += '\n';
      });

      resultText += `\nTo set up real monitoring, you could use the OpenSearch _search API with a persistent connection or implement a polling mechanism in your application.`;
      
      return resultText;
    }, `Failed to monitor logs for index ${args.index}. The index may not exist or the connection timed out.`);
  },
});

// Tool to search Wazuh alerts
server.addTool({
  name: "searchAlerts",
  description: "Search for security alerts in Wazuh data",
  parameters: z.object({
    query: z.string().describe("The search query text"),
    timeRange: z.string().default("24h").describe("Time range (e.g., 1h, 24h, 7d)"),
    maxResults: z.number().default(10).describe("Maximum number of results to return"),
    index: z.string().default("wazuh-alerts-*").describe("Index pattern to search"),
  }),
  execute: async (args, { log }) => {
    log.info("Searching alerts", { query: args.query, timeRange: args.timeRange });

    return safeOpenSearchQuery(async () => {
      const timeRangeMs = parseTimeRange(args.timeRange);
      const now = new Date();
      const from = new Date(now.getTime() - timeRangeMs);

      const response = await client.search({
        index: args.index,
        body: {
          size: args.maxResults,
          query: {
            bool: {
              must: [
                { query_string: { query: args.query } },
                {
                  range: {
                    timestamp: {
                      gte: from.toISOString(),
                      lte: now.toISOString(),
                    },
                  },
                },
              ],
            },
          },
          sort: [{ timestamp: { order: "desc" } }],
          timeout: "25s"
        },
      });

      const hits = response.body.hits.hits || [];
      const total = response.body.hits.total?.value || 0;

      log.info(`Found ${total} matching alerts`, { count: total });

      if (hits.length === 0) {
        return "No alerts found matching your criteria.";
      }

      const results = hits.map(hit => {
        const source = hit._source;
        return {
          id: hit._id,
          timestamp: source.timestamp,
          rule: source.rule?.description || "No description",
          level: source.rule?.level || 0,
          agent: source.agent?.name || "Unknown",
          message: source.data?.title || source.rule?.description || "No message",
          details: JSON.stringify(source, null, 2)
        };
      });

      let resultText = `Found ${total} alerts matching your criteria. Showing top ${hits.length}:\n\n`;
      
      results.forEach((alert, i) => {
        resultText += `### Alert ${i+1}\n`;
        resultText += `- **Time**: ${alert.timestamp}\n`;
        resultText += `- **Level**: ${alert.level}\n`;
        resultText += `- **Rule**: ${alert.rule}\n`;
        resultText += `- **Agent**: ${alert.agent}\n`;
        resultText += `- **Message**: ${alert.message}\n\n`;
      });

      return resultText;
    }, "Failed to search alerts. The query may be invalid or the server connection timed out.");
  },
});

// Tool to get alert details
server.addTool({
  name: "getAlertDetails",
  description: "Get detailed information about a specific alert by ID",
  parameters: z.object({
    id: z.string().describe("The alert ID"),
    index: z.string().default("wazuh-alerts-*").describe("Index pattern"),
  }),
  execute: async (args, { log }) => {
    log.info("Getting alert details", { id: args.id });

    return safeOpenSearchQuery(async () => {
      const response = await client.get({
        index: args.index,
        id: args.id,
        timeout: "15s"
      });

      const source = response.body._source;
      
      return `## Alert Details\n\n\`\`\`json\n${JSON.stringify(source, null, 2)}\n\`\`\``;
    }, `Failed to get details for alert ID ${args.id}. The alert may not exist or the connection timed out.`);
  },
});

// Tool to generate alert statistics
server.addTool({
  name: "alertStatistics",
  description: "Get statistics about security alerts",
  parameters: z.object({
    timeRange: z.string().default("24h").describe("Time range (e.g., 1h, 24h, 7d)"),
    field: z.string().default("rule.level").describe("Field to aggregate by"),
    index: z.string().default("wazuh-alerts-*").describe("Index pattern"),
  }),
  execute: async (args, { log }) => {
    log.info("Getting alert statistics", { timeRange: args.timeRange, field: args.field });

    return safeOpenSearchQuery(async () => {
      const timeRangeMs = parseTimeRange(args.timeRange);
      const now = new Date();
      const from = new Date(now.getTime() - timeRangeMs);

      const response = await client.search({
        index: args.index,
        body: {
          size: 0,
          query: {
            range: {
              timestamp: {
                gte: from.toISOString(),
                lte: now.toISOString(),
              },
            },
          },
          aggs: {
            stats: {
              terms: {
                field: args.field,
                size: 20,
              },
            },
          },
          timeout: "25s"
        },
      });

      const buckets = response.body.aggregations?.stats?.buckets || [];
      const total = buckets.reduce((sum, bucket) => sum + bucket.doc_count, 0);

      log.info(`Found statistics for ${total} alerts`, { count: total });

      if (total === 0) {
        return "No alerts found in the specified time range.";
      }

      let resultText = `## Alert Statistics for the past ${args.timeRange}\n\n`;
      resultText += `Total alerts: ${total}\n\n`;
      
      resultText += `### Breakdown by ${args.field}\n\n`;
      buckets.forEach(bucket => {
        const percentage = ((bucket.doc_count / total) * 100).toFixed(2);
        resultText += `- **${bucket.key}**: ${bucket.doc_count} (${percentage}%)\n`;
      });

      return resultText;
    }, `Failed to get alert statistics. The field "${args.field}" may not be aggregatable or the connection timed out.`);
  },
});

// Tool to create a dashboard visualization
server.addTool({
  name: "visualizeAlertTrend",
  description: "Visualize alert trends over time",
  parameters: z.object({
    timeRange: z.string().default("7d").describe("Time range (e.g., 1h, 24h, 7d)"),
    interval: z.string().default("1d").describe("Time interval for grouping (e.g., 1h, 1d)"),
    query: z.string().default("*").describe("Query to filter alerts"),
    index: z.string().default("wazuh-alerts-*").describe("Index pattern"),
  }),
  execute: async (args, { log, reportProgress }) => {
    log.info("Generating visualization", { 
      timeRange: args.timeRange, 
      interval: args.interval,
      query: args.query
    });

    reportProgress({
      progress: 0,
      total: 100,
      message: "Starting visualization generation..."
    });

    return safeOpenSearchQuery(async () => {
      const timeRangeMs = parseTimeRange(args.timeRange);
      const now = new Date();
      const from = new Date(now.getTime() - timeRangeMs);

      reportProgress({
        progress: 30,
        total: 100,
        message: "Querying OpenSearch..."
      });

      const response = await client.search({
        index: args.index,
        body: {
          size: 0,
          query: {
            bool: {
              must: [
                { query_string: { query: args.query } },
                {
                  range: {
                    timestamp: {
                      gte: from.toISOString(),
                      lte: now.toISOString(),
                    },
                  },
                },
              ],
            },
          },
          aggs: {
            alerts_over_time: {
              date_histogram: {
                field: "timestamp",
                calendar_interval: args.interval,
                format: "yyyy-MM-dd HH:mm:ss",
              },
              aggs: {
                rule_levels: {
                  terms: {
                    field: "rule.level",
                    size: 15,
                  },
                },
              },
            },
          },
          timeout: "45s" // Longer timeout for visualization requests
        },
      });

      reportProgress({
        progress: 70,
        total: 100,
        message: "Processing visualization data..."
      });

      const buckets = response.body.aggregations?.alerts_over_time?.buckets || [];
      
      if (buckets.length === 0) {
        return "No data available for visualization in the specified time range.";
      }
      
      // Generate visualization from data
      const timePoints = buckets.map(b => b.key_as_string.split(' ')[0]);
      const counts = buckets.map(b => b.doc_count);
      
      let resultText = `## Alert Trend for the past ${args.timeRange}\n\n`;
      resultText += `Query: ${args.query}\n\n`;
      
      // Simple text-based chart
      const maxCount = Math.max(...counts);
      const chartHeight = 10;
      
      resultText += "```\n";
      for (let i = chartHeight; i > 0; i--) {
        const threshold = maxCount * (i / chartHeight);
        let line = counts.map(count => count >= threshold ? '█' : ' ').join('');
        resultText += line + "\n";
      }
      
      // X-axis dates
      resultText += timePoints.map(d => d.substring(5)).join(' ') + "\n";
      resultText += "```\n\n";
      
      // Table format
      resultText += "| Date | Count |\n";
      resultText += "|------|-------|\n";
      for (let i = 0; i < timePoints.length; i++) {
        resultText += `| ${timePoints[i]} | ${counts[i]} |\n`;
      }
      
      reportProgress({
        progress: 100,
        total: 100,
        message: "Visualization complete"
      });

      return resultText;
    }, "Failed to generate alert visualization. The query may be too complex or the connection timed out.");
  },
});

// Helper function to parse time range strings like "1h", "24h", "7d"
function parseTimeRange(timeRange) {
  const unit = timeRange.slice(-1);
  const value = parseInt(timeRange.slice(0, -1));
  
  debugLog('Parsing time range:', timeRange, 'to milliseconds');
  
  switch (unit) {
    case 'h':
      return value * 60 * 60 * 1000; // hours to ms
    case 'd':
      return value * 24 * 60 * 60 * 1000; // days to ms
    case 'w':
      return value * 7 * 24 * 60 * 60 * 1000; // weeks to ms
    case 'm':
      return value * 30 * 24 * 60 * 60 * 1000; // months to ms (approximate)
    default:
      const error = `Invalid time range format: ${timeRange}`;
      debugLog('Error:', error);
      throw new Error(error);
  }
}

// Add debug event listeners to monitor MCP server activity
server.onAny((event, ...args) => {
  debugLog(`MCP Event: ${event}`, ...args);
});

// Start the MCP server with stdio transport
debugLog('Starting MCP server with stdio transport');
server.start({
  transportType: "stdio"
});

console.log('OpenSearch MCP Server running in stdio mode');
console.log('To enable debug logging, set DEBUG=true in your .env file');