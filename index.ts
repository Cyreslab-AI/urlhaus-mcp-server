#!/usr/bin/env node

/**
 * URLhaus MCP Server
 * 
 * This MCP server provides access to URLhaus (https://urlhaus.abuse.ch/),
 * a project from abuse.ch that collects and shares malicious URLs used for
 * malware distribution.
 * 
 * URLhaus API endpoints:
 * - Recent URLs: Get the most recent malicious URLs
 * - URL Info: Get detailed information about a specific URL
 * - Host Info: Get information about URLs hosted on a specific host
 * - URL Search: Search for URLs by various criteria
 * - Payload Info: Get information about malware payloads
 * - Tag Info: Get URLs associated with specific tags
 * 
 * The URLhaus API is free to use and doesn't require authentication,
 * but has rate limits to prevent abuse.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from 'axios';

interface URLhausURL {
  id: string;
  urlhaus_reference: string;
  url: string;
  url_status: string;
  host: string;
  date_added: string;
  threat: string;
  blacklists: any;
  reporter: string;
  larted: string;
  takedown_time_seconds?: number;
  tags: string[];
}

interface URLhausHost {
  host: string;
  firstseen: string;
  url_count: number;
  blacklists: any;
  urls: URLhausURL[];
}

interface URLhausPayload {
  md5_hash: string;
  sha256_hash: string;
  file_type: string;
  file_size: number;
  signature?: string;
  firstseen: string;
  lastseen: string;
  url_count: number;
  urlhaus_download: string;
  virustotal: any;
  imphash?: string;
  ssdeep?: string;
  tlsh?: string;
}

class URLhausServer {
  private server: Server;
  private axiosInstance: AxiosInstance;

  constructor() {
    this.server = new Server(
      {
        name: "urlhaus-server",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // URLhaus API configuration
    this.axiosInstance = axios.create({
      baseURL: 'https://urlhaus-api.abuse.ch/v1',
      timeout: 30000,
      headers: {
        'User-Agent': 'URLhaus-MCP-Server/0.1.0',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    this.setupToolHandlers();
    
    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'get_recent_urls',
          description: 'Get the most recent malicious URLs from URLhaus (up to 1000 entries)',
          inputSchema: {
            type: 'object',
            properties: {
              limit: {
                type: 'number',
                description: 'Number of URLs to retrieve (1-1000, default: 100)',
                minimum: 1,
                maximum: 1000,
              },
            },
          },
        },
        {
          name: 'lookup_url',
          description: 'Get detailed information about a specific URL',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'The URL to look up (must be a complete URL with protocol)',
              },
            },
            required: ['url'],
          },
        },
        {
          name: 'lookup_host',
          description: 'Get information about URLs hosted on a specific host/domain',
          inputSchema: {
            type: 'object',
            properties: {
              host: {
                type: 'string',
                description: 'The hostname or domain to look up (e.g., "example.com")',
              },
            },
            required: ['host'],
          },
        },

        {
          name: 'lookup_payload',
          description: 'Get information about a malware payload by its hash',
          inputSchema: {
            type: 'object',
            properties: {
              hash: {
                type: 'string',
                description: 'MD5 or SHA256 hash of the malware payload',
              },
            },
            required: ['hash'],
          },
        },
        {
          name: 'get_urls_by_tag',
          description: 'Get URLs associated with a specific malware tag/family',
          inputSchema: {
            type: 'object',
            properties: {
              tag: {
                type: 'string',
                description: 'Malware tag/family (e.g., "emotet", "trickbot", "cobalt_strike")',
              },
              limit: {
                type: 'number',
                description: 'Number of results to return (1-1000, default: 100)',
                minimum: 1,
                maximum: 1000,
              },
            },
            required: ['tag'],
          },
        },
        {
          name: 'get_urls_by_signature',
          description: 'Get URLs associated with a specific malware signature',
          inputSchema: {
            type: 'object',
            properties: {
              signature: {
                type: 'string',
                description: 'Malware signature name',
              },
              limit: {
                type: 'number',
                description: 'Number of results to return (1-1000, default: 100)',
                minimum: 1,
                maximum: 1000,
              },
            },
            required: ['signature'],
          },
        },
        {
          name: 'get_payloads',
          description: 'Get recent malware payloads from URLhaus',
          inputSchema: {
            type: 'object',
            properties: {
              limit: {
                type: 'number',
                description: 'Number of payloads to retrieve (1-1000, default: 100)',
                minimum: 1,
                maximum: 1000,
              },
            },
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        switch (request.params.name) {
          case 'get_recent_urls':
            return await this.getRecentUrls(request.params.arguments);
          case 'lookup_url':
            return await this.lookupUrl(request.params.arguments);
          case 'lookup_host':
            return await this.lookupHost(request.params.arguments);

          case 'lookup_payload':
            return await this.lookupPayload(request.params.arguments);
          case 'get_urls_by_tag':
            return await this.getUrlsByTag(request.params.arguments);
          case 'get_urls_by_signature':
            return await this.getUrlsBySignature(request.params.arguments);
          case 'get_payloads':
            return await this.getPayloads(request.params.arguments);
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${request.params.name}`
            );
        }
      } catch (error) {
        if (axios.isAxiosError(error)) {
          const statusCode = error.response?.status;
          const errorMessage = error.response?.data?.query_status || error.message;
          
          if (statusCode === 429) {
            return {
              content: [{
                type: 'text',
                text: `Rate limit exceeded. Please try again later.`
              }],
              isError: true,
            };
          }
          
          return {
            content: [{
              type: 'text',
              text: `URLhaus API error (${statusCode}): ${errorMessage}`
            }],
            isError: true,
          };
        }
        
        throw error;
      }
    });
  }

  private async getRecentUrls(args: any) {
    const limit = Math.min(Number(args?.limit || 100), 1000);

    const response = await this.axiosInstance.get('/urls/recent/', {
      params: { limit }
    });

    const data = response.data;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query_status: data.query_status,
          urls_count: data.urls?.length || 0,
          urls: data.urls?.slice(0, limit) || [],
          summary: `Retrieved ${data.urls?.length || 0} recent malicious URLs`
        }, null, 2)
      }]
    };
  }

  private async lookupUrl(args: any) {
    const url = String(args?.url || '').trim();
    
    if (!url) {
      throw new McpError(ErrorCode.InvalidParams, 'URL parameter is required');
    }

    const formData = new URLSearchParams();
    formData.append('url', url);

    const response = await this.axiosInstance.post('/url/', formData);
    const data = response.data;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query_status: data.query_status,
          url_info: data,
          summary: data.query_status === 'ok' ? 
            `URL found in URLhaus database` : 
            `URL not found in URLhaus database`
        }, null, 2)
      }]
    };
  }

  private async lookupHost(args: any) {
    const host = String(args?.host || '').trim();
    
    if (!host) {
      throw new McpError(ErrorCode.InvalidParams, 'Host parameter is required');
    }

    const formData = new URLSearchParams();
    formData.append('host', host);

    const response = await this.axiosInstance.post('/host/', formData);
    const data = response.data;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query_status: data.query_status,
          host_info: data,
          urls_count: data.urls?.length || 0,
          summary: data.query_status === 'ok' ? 
            `Found ${data.urls?.length || 0} URLs for host ${host}` : 
            `No data found for host ${host}`
        }, null, 2)
      }]
    };
  }



  private async lookupPayload(args: any) {
    const hash = String(args?.hash || '').trim();
    
    if (!hash) {
      throw new McpError(ErrorCode.InvalidParams, 'Hash parameter is required');
    }

    const formData = new URLSearchParams();
    formData.append('hash', hash);

    const response = await this.axiosInstance.post('/payload/', formData);
    const data = response.data;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query_status: data.query_status,
          payload_info: data,
          summary: data.query_status === 'ok' ? 
            `Payload found in URLhaus database` : 
            `Payload not found in URLhaus database`
        }, null, 2)
      }]
    };
  }

  private async getUrlsByTag(args: any) {
    const tag = String(args?.tag || '').trim();
    const limit = Math.min(Number(args?.limit || 100), 1000);
    
    if (!tag) {
      throw new McpError(ErrorCode.InvalidParams, 'Tag parameter is required');
    }

    const formData = new URLSearchParams();
    formData.append('tag', tag);
    formData.append('limit', limit.toString());

    const response = await this.axiosInstance.post('/tag/', formData);
    const data = response.data;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query_status: data.query_status,
          tag: tag,
          urls_count: data.urls?.length || 0,
          urls: data.urls?.slice(0, limit) || [],
          summary: `Found ${data.urls?.length || 0} URLs tagged with "${tag}"`
        }, null, 2)
      }]
    };
  }

  private async getUrlsBySignature(args: any) {
    const signature = String(args?.signature || '').trim();
    const limit = Math.min(Number(args?.limit || 100), 1000);
    
    if (!signature) {
      throw new McpError(ErrorCode.InvalidParams, 'Signature parameter is required');
    }

    const formData = new URLSearchParams();
    formData.append('signature', signature);
    formData.append('limit', limit.toString());

    const response = await this.axiosInstance.post('/signature/', formData);
    const data = response.data;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query_status: data.query_status,
          signature: signature,
          urls_count: data.urls?.length || 0,
          urls: data.urls?.slice(0, limit) || [],
          summary: `Found ${data.urls?.length || 0} URLs with signature "${signature}"`
        }, null, 2)
      }]
    };
  }

  private async getPayloads(args: any) {
    const limit = Math.min(Number(args?.limit || 100), 1000);

    const response = await this.axiosInstance.get('/payloads/recent/', {
      params: { limit }
    });

    const data = response.data;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query_status: data.query_status,
          payloads_count: data.payloads?.length || 0,
          payloads: data.payloads?.slice(0, limit) || [],
          summary: `Retrieved ${data.payloads?.length || 0} recent malware payloads`
        }, null, 2)
      }]
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('URLhaus MCP server running on stdio');
  }
}

const server = new URLhausServer();
server.run().catch(console.error);
