// OpenSearch MCP Server
import { FastMCP, UserError, imageContent } from "fastmcp";
import { Client } from "@opensearch-project/opensearch";
import { z } from "zod";
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Configure OpenSearch client
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
});

// Initialize MCP Server
const server = new FastMCP({
  name: "OpenSearch Security Analytics",
  version: "1.0.0",
  description: "MCP server for querying Wazuh security logs in OpenSearch",
});

// Tool to list all available indexes
server.addTool({
  name: "listIndexes",
  description: "List all available indexes in OpenSearch",
  parameters: z.object({
    pattern: z.string().default("*").describe("Index pattern to filter (e.g., 'logs-*')"),
  }),
  execute: async (args, { log }) => {
    log.info("Listing indexes", { pattern: args.pattern });

    try {
      const response = await client.cat.indices({
        format: "json",
        index: args.pattern,
      });

      const indexes = response.body;
      
      if (indexes.length === 0) {
        return "No indexes found matching your pattern.";
      }

      // Sort indexes by size (descending)
      indexes.sort((a, b) => parseInt(b.pri_store_size) - parseInt(a.pri_store_size));

      let resultText = `## Available Indexes (${indexes.length} total)\n\n`;
      resultText += "| Index | Docs Count | Size | Status | Health |\n";
      resultText += "|-------|------------|------|--------|--------|\n";
      
      indexes.forEach(idx => {
        resultText += `| ${idx.index} | ${idx.docs?.count || 'N/A'} | ${idx.pri.store.size || 'N/A'} | ${idx.status} | ${idx.health} |\n`;
      });

      return resultText;
    } catch (error) {
      log.error("Error listing indexes", { error: error.message });
      throw new UserError(`Failed to list indexes: ${error.message}`);
    }
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

    try {
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
        sort: [{ [args.timeField]: { order: "desc" } }]
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

      const hits = response.body.hits.hits;
      const total = response.body.hits.total.value;

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
    } catch (error) {
      log.error("Error searching logs", { error: error.message });
      throw new UserError(`Failed to search logs: ${error.message}`);
    }
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

    try {
      const response = await client.indices.getMapping({
        index: args.index
      });

      const mappings = response.body;
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
    } catch (error) {
      log.error("Error getting index mapping", { error: error.message });
      throw new UserError(`Failed to get index mapping: ${error.message}`);
    }
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

    try {
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
          }
        }
      });

      const buckets = response.body.aggregations?.field_values?.buckets || [];
      const total = response.body.hits.total.value;
      
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
    } catch (error) {
      log.error("Error exploring field values", { error: error.message });
      throw new UserError(`Failed to explore field values: ${error.message}`);
    }
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
    try {
      reportProgress({
        progress: 10,
        total: 100,
        message: "Preparing log monitoring..."
      });

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
          ]
        }
      });

      const hits = response.body.hits.hits;
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
        resultText += `**Log ${i+1}** (${new Date(source['@timestamp'] || source.timestamp).toLocaleString()}):\n`;
        
        // Show a summary with key fields
        const importantFields = ['message', 'level', 'logger_name', 'status', 'method', 'path'];
        importantFields.forEach(field => {
          if (source[field]) {
            resultText += `- **${field}**: ${source[field]}\n`;
          }
        });
        
        resultText += '\n';
      });

      resultText += `\nTo set up real monitoring, you could use the OpenSearch _search API with a persistent connection or implement a polling mechanism in your application.`;
      
      return resultText;
    } catch (error) {
      log.error("Error monitoring logs", { error: error.message });
      throw new UserError(`Failed to monitor logs: ${error.message}`);
    }
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

    try {
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
        },
      });

      const hits = response.body.hits.hits;
      const total = response.body.hits.total.value;

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
    } catch (error) {
      log.error("Error searching alerts", { error: error.message });
      throw new UserError(`Failed to search alerts: ${error.message}`);
    }
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

    try {
      const response = await client.get({
        index: args.index,
        id: args.id,
      });

      const source = response.body._source;
      
      return `## Alert Details\n\n\`\`\`json\n${JSON.stringify(source, null, 2)}\n\`\`\``;
    } catch (error) {
      log.error("Error getting alert details", { error: error.message });
      throw new UserError(`Failed to get alert details: ${error.message}`);
    }
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

    try {
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
        },
      });

      const buckets = response.body.aggregations.stats.buckets;
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
    } catch (error) {
      log.error("Error getting alert statistics", { error: error.message });
      throw new UserError(`Failed to get alert statistics: ${error.message}`);
    }
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
    });

    try {
      const timeRangeMs = parseTimeRange(args.timeRange);
      const now = new Date();
      const from = new Date(now.getTime() - timeRangeMs);

      reportProgress({
        progress: 30,
        total: 100,
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
        },
      });

      reportProgress({
        progress: 70,
        total: 100,
      });

      const buckets = response.body.aggregations.alerts_over_time.buckets;
      
      // You could generate a real chart image here using a library like ChartJS
      // For now, we'll return a text-based visualization
      
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
      });

      return resultText;
    } catch (error) {
      log.error("Error generating visualization", { error: error.message });
      throw new UserError(`Failed to generate visualization: ${error.message}`);
    }
  },
});

// Helper function to parse time range strings like "1h", "24h", "7d"
function parseTimeRange(timeRange) {
  const unit = timeRange.slice(-1);
  const value = parseInt(timeRange.slice(0, -1));
  
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
      throw new Error(`Invalid time range format: ${timeRange}`);
  }
}

// Start the MCP server
server.start({
  transportType: "sse",
  sse: {
    endpoint: "/sse",
    port: parseInt(process.env.PORT || "3000"),
  },
});

console.log(`OpenSearch MCP Server running at http://localhost:${process.env.PORT || 3000}/sse`);