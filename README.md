# URLhaus MCP Server

[![npm version](https://badge.fury.io/js/urlhaus-mcp-server.svg)](https://badge.fury.io/js/urlhaus-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)

A comprehensive Model Context Protocol (MCP) server that provides access to [URLhaus](https://urlhaus.abuse.ch/), a project from abuse.ch that collects and shares malicious URLs used for malware distribution. This server enables AI agents to perform threat intelligence research and cybersecurity analysis through the URLhaus database.

## Features

This MCP server provides the following tools for querying URLhaus data:

### URL Analysis Tools
- **get_recent_urls**: Get the most recent malicious URLs from URLhaus
- **lookup_url**: Get detailed information about a specific URL
- **search_urls**: Search for URLs by various criteria (host, URL, tag, or signature)

### Host/Domain Analysis Tools
- **lookup_host**: Get information about URLs hosted on a specific host/domain

### Malware Analysis Tools
- **lookup_payload**: Get information about a malware payload by its hash
- **get_payloads**: Get recent malware payloads from URLhaus
- **get_urls_by_tag**: Get URLs associated with a specific malware tag/family
- **get_urls_by_signature**: Get URLs associated with a specific malware signature

## Installation

### From GitHub

1. Clone the repository:
   ```bash
   git clone https://github.com/Cyreslab-AI/urlhaus-mcp-server.git
   cd urlhaus-mcp-server
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the server:
   ```bash
   npm run build
   ```

### From npm (Coming Soon)

```bash
npm install -g urlhaus-mcp-server
```

## Configuration

Add the server to your MCP settings configuration:

```json
{
  "mcpServers": {
    "urlhaus": {
      "command": "node",
      "args": ["/path/to/urlhaus-mcp-server/build/index.js"]
    }
  }
}
```

No API keys or authentication are required as URLhaus provides a free public API.

## Usage Examples

### Get Recent Malicious URLs
```json
{
  "tool": "get_recent_urls",
  "arguments": {
    "limit": 50
  }
}
```

### Look Up a Specific URL
```json
{
  "tool": "lookup_url",
  "arguments": {
    "url": "https://suspicious-domain.com/malware.exe"
  }
}
```

### Search for URLs by Host
```json
{
  "tool": "search_urls",
  "arguments": {
    "search_term": "malicious-domain.com",
    "limit": 100
  }
}
```

### Get URLs by Malware Family
```json
{
  "tool": "get_urls_by_tag",
  "arguments": {
    "tag": "emotet",
    "limit": 50
  }
}
```

### Look Up Malware Payload
```json
{
  "tool": "lookup_payload",
  "arguments": {
    "hash": "d41d8cd98f00b204e9800998ecf8427e"
  }
}
```

## API Rate Limits

URLhaus has rate limits to prevent abuse. If you encounter rate limiting, wait before making additional requests.

## Data Format

All responses include:
- `query_status`: Status of the API query ("ok" or error message)
- `summary`: Human-readable summary of results
- Data specific to the query type (URLs, payloads, etc.)

## About URLhaus

URLhaus is operated by abuse.ch and provides:
- Real-time feed of malicious URLs
- Information about malware payloads
- Integration with various threat intelligence platforms
- Free access to security researchers and defenders

For more information, visit: https://urlhaus.abuse.ch/

## Development

To run in development mode:
```bash
npm run watch
```

To inspect the server:
```bash
npm run inspector
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [URLhaus](https://urlhaus.abuse.ch/) by abuse.ch for providing the free threat intelligence API
- [Model Context Protocol](https://modelcontextprotocol.io/) for the MCP framework
- [Cyreslab AI](https://github.com/Cyreslab-AI) for development and maintenance

## Support

If you encounter any issues or have questions, please [open an issue](https://github.com/Cyreslab-AI/urlhaus-mcp-server/issues) on GitHub.
