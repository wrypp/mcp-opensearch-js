# OpenSearch MCP Server

A Model Context Protocol (MCP) server for querying and analyzing Wazuh security logs stored in OpenSearch.

## Features

- Search for security alerts with advanced filtering
- Get detailed information about specific alerts
- Generate statistics on security events
- Visualize alert trends over time
- Progress reporting for long-running operations
- Structured error handling

## Prerequisites

- Node.js v16 or higher
- Access to an OpenSearch instance containing Wazuh security logs

## Installation

1. Clone this repository:
```bash
git clone <your-repo-url>
cd mcp-opensearch-js
```

2. Install dependencies:
```bash
npm install
```

3. Configure your environment variables:
```bash
cp .env.example .env
```

4. Edit the `.env` file with your OpenSearch connection details:
```
OPENSEARCH_URL=https://your-opensearch-endpoint:9200
OPENSEARCH_USERNAME=your-username
OPENSEARCH_PASSWORD=your-password
PORT=3000
```

## Running the Server

### Start the server:

```bash
npm start
```

This will start the server at `http://localhost:3000/sse`.

### Test with MCP CLI:

```bash
npm run dev
```

This runs the server with the FastMCP CLI tool for interactive testing.

### Test with MCP Inspector:

```bash
npm run inspect
```

This starts the server and connects it to the MCP Inspector for visual debugging.

## Server Tools

The server provides the following tools:

### 1. Search Alerts

Search for security alerts in Wazuh data.

**Parameters:**
- `query`: The search query text
- `timeRange`: Time range (e.g., 1h, 24h, 7d)
- `maxResults`: Maximum number of results to return
- `index`: Index pattern to search

### 2. Get Alert Details

Get detailed information about a specific alert by ID.

**Parameters:**
- `id`: The alert ID
- `index`: Index pattern

### 3. Alert Statistics

Get statistics about security alerts.

**Parameters:**
- `timeRange`: Time range (e.g., 1h, 24h, 7d)
- `field`: Field to aggregate by (e.g., rule.level, agent.name)
- `index`: Index pattern

### 4. Visualize Alert Trend

Visualize alert trends over time.

**Parameters:**
- `timeRange`: Time range (e.g., 1h, 24h, 7d)
- `interval`: Time interval for grouping (e.g., 1h, 1d)
- `query`: Query to filter alerts
- `index`: Index pattern

## Example Usage

Using the MCP CLI tool:

```
> tools
Available tools:
- searchAlerts: Search for security alerts in Wazuh data
- getAlertDetails: Get detailed information about a specific alert by ID
- alertStatistics: Get statistics about security alerts
- visualizeAlertTrend: Visualize alert trends over time

> tools.searchAlerts(query: "rule.level:>10", timeRange: "12h", maxResults: 5)
```

## Using with a Client

To use this MCP server with a client implementation:

```javascript
import { Client } from "@modelcontextprotocol/sdk";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const client = new Client(
  {
    name: "example-client",
    version: "1.0.0",
  },
  {
    capabilities: {},
  },
);

const transport = new SSEClientTransport(new URL(`http://localhost:3000/sse`));

await client.connect(transport);

// Use tools
const result = await client.executeTool("searchAlerts", {
  query: "rule.level:>10",
  timeRange: "24h",
  maxResults: 10
});

console.log(result);
```

## License

MIT