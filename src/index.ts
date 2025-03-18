#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import crypto from 'crypto';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

interface CreateClusterInput {
  projectId: string;
  clusterName: string;
  region: string;
  cloudProvider: string;
  tier: string;
}

interface NetworkAccessInput {
  projectId: string;
  ipAddresses: string[];
}

interface CreateUserInput {
  projectId: string;
  username: string;
  password: string;
  roles: string[];
}

interface ConnectionStringsInput {
  projectId: string;
  clusterName: string;
}

interface ListClustersInput {
  projectId: string;
}

const isValidCreateClusterInput = (args: any): args is CreateClusterInput =>
  typeof args === 'object' &&
  args !== null &&
  typeof args.projectId === 'string' &&
  typeof args.clusterName === 'string' &&
  typeof args.region === 'string' &&
  typeof args.cloudProvider === 'string' &&
  typeof args.tier === 'string';

class AtlasProjectManager {
  private server: Server;
  private apiKey: string;
  private privateKey: string;

  private async makeAtlasRequest(url: string, method: string, body?: any) {
    // Step 1: Make initial request to get digest challenge
    const initialResponse = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json'
      },
      body: body ? JSON.stringify(body) : undefined
    });

    // Check if we got a 401 with WWW-Authenticate header (digest challenge)
    if (initialResponse.status === 401) {
      const wwwAuthHeader = initialResponse.headers.get('WWW-Authenticate');
      if (!wwwAuthHeader || !wwwAuthHeader.startsWith('Digest ')) {
        throw new Error('Expected Digest authentication challenge not received');
      }

      // Parse the digest challenge
      const authDetails: Record<string, string> = {};
      wwwAuthHeader.substring(7).split(',').forEach(part => {
        const [key, value] = part.trim().split('=');
        // Remove quotes if present
        authDetails[key] = value.startsWith('"') ? value.slice(1, -1) : value;
      });

      // Generate a random client nonce (cnonce)
      const cnonce = Math.random().toString(36).substring(2, 15);
      const nc = '00000001'; // nonce count, incremented for each request with the same nonce

      // Calculate the response hash
      const ha1 = this.md5(`${this.apiKey}:${authDetails.realm}:${this.privateKey}`);
      const ha2 = this.md5(`${method}:${new URL(url).pathname}`);
      const response = this.md5(`${ha1}:${authDetails.nonce}:${nc}:${cnonce}:${authDetails.qop}:${ha2}`);

      // Build the Authorization header
      const authHeader = `Digest username="${this.apiKey}", realm="${authDetails.realm}", nonce="${authDetails.nonce}", uri="${new URL(url).pathname}", qop=${authDetails.qop}, nc=${nc}, cnonce="${cnonce}", response="${response}", algorithm=${authDetails.algorithm || 'MD5'}`;

      // Make the actual request with the digest authentication
      const digestResponse = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authHeader
        },
        body: body ? JSON.stringify(body) : undefined
      });

      if (!digestResponse.ok) {
        throw new Error(`Atlas API error: ${digestResponse.statusText}`);
      }

      return digestResponse.json();
    } else if (initialResponse.ok) {
      // If the initial request succeeded without authentication (unlikely)
      return initialResponse.json();
    } else {
      throw new Error(`Atlas API error: ${initialResponse.statusText}`);
    }
  }

  // Helper method to calculate MD5 hash
  private md5(data: string): string {
    // Use createRequire to enable require in ES modules
    return crypto.createHash('md5').update(data).digest('hex');
  }

  private async createAtlasCluster(input: CreateClusterInput) {
    if (input.tier === 'M0') {
      return {
        content: [{
          type: 'text',
          text: 'M0 (Free Tier) clusters cannot be created via the API. Please use the MongoDB Atlas UI to create an M0 cluster.'
        }],
        isError: true
      };
    }

    try {
      const url = `https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/clusters?pretty=true`;
      const body = {
        name: input.clusterName,
        providerSettings: {
          providerName: input.cloudProvider,
          instanceSizeName: input.tier,
          regionName: input.region
        }
      };

      const result = await this.makeAtlasRequest(url, 'POST', body);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: 'text',
          text: error.message
        }],
        isError: true
      };
    }
  }

  private async setupAtlasNetworkAccess(input: NetworkAccessInput) {
    try {
      const url = `https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/accessList`;
      const body = input.ipAddresses.map(ip => ({
        ipAddress: ip,
        comment: "Added via Atlas Project Manager MCP"
      }));

      const result = await this.makeAtlasRequest(url, 'POST', body);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: 'text',
          text: error.message
        }],
        isError: true
      };
    }
  }

  private async createAtlasUser(input: CreateUserInput) {
    try {
      const url = `https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/databaseUsers`;
      const body = {
        databaseName: "admin",
        username: input.username,
        password: input.password,
        roles: input.roles.map(role => ({ databaseName: 'admin', roleName: role }))
      };

      const result = await this.makeAtlasRequest(url, 'POST', body);
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: 'text',
          text: error.message
        }],
        isError: true
      };
    }
  }

  private async getAtlasConnectionStrings(input: ConnectionStringsInput) {
    try {
      const url = `https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/clusters/${input.clusterName}`;
      const result = await this.makeAtlasRequest(url, 'GET');
      
      // Add appName to connection strings if they exist
      if (result.connectionStrings) {
        this.addAppNameToConnectionStrings(result);
      }
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: 'text',
          text: error.message
        }],
        isError: true
      };
    }
  }

  private async listAtlasProjects() {
    try {
      const url = 'https://cloud.mongodb.com/api/atlas/v1.0/groups';
      const result = await this.makeAtlasRequest(url, 'GET');
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: 'text',
          text: error.message
        }],
        isError: true
      };
    }
  }

  // Helper method to add appName to connection strings
  private addAppNameToConnectionStrings(result: any) {
    const appName = "devrel.integration.mcp-atlas";
    
    // Helper function to safely add appName parameter to a connection string
    const addAppNameParam = (connectionString: string): string => {
      if (!connectionString) return connectionString;
      
      // Add appName parameter
      return connectionString + (connectionString.includes('?') ? '&' : '?') + `appName=${appName}`;
    };
    
    // Handle single cluster object
    if (result.connectionStrings) {
      // Add appName to standard connection string
      if (result.connectionStrings.standard) {
        result.connectionStrings.standard = addAppNameParam(result.connectionStrings.standard);
      }
      
      // Add appName to standardSrv connection string
      if (result.connectionStrings.standardSrv) {
        result.connectionStrings.standardSrv = addAppNameParam(result.connectionStrings.standardSrv);
      }
      
      // Add appName to other connection string formats
      if (result.mongoURI) {
        result.mongoURI = addAppNameParam(result.mongoURI);
      }
      
      if (result.mongoURIWithOptions) {
        result.mongoURIWithOptions = addAppNameParam(result.mongoURIWithOptions);
      }
      
      if (result.srvAddress) {
        result.srvAddress = addAppNameParam(result.srvAddress);
      }
    }
    
    // Handle array of clusters (for listAtlasClusters)
    if (result.results && Array.isArray(result.results)) {
      result.results.forEach((cluster: any) => {
        if (cluster.connectionStrings) {
          this.addAppNameToConnectionStrings(cluster);
        }
      });
    }
    
    return result;
  }

  private async listAtlasClusters(input: ListClustersInput) {
    try {
      const url = `https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/clusters`;
      const result = await this.makeAtlasRequest(url, 'GET');
      
      // Add appName to connection strings in all clusters
      this.addAppNameToConnectionStrings(result);
      
      return {
        content: [{
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error: any) {
      return {
        content: [{
          type: 'text',
          text: error.message
        }],
        isError: true
      };
    }
  }

  constructor() {
    this.server = new Server(
      {
        name: 'atlas-project-manager',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    let apiKey = process.env.ATLAS_PUBLIC_KEY;
    let privateKey = process.env.ATLAS_PRIVATE_KEY;

    if (!apiKey || !privateKey) {
      const args = process.argv.slice(2);
      if (args.length >= 2) {
        apiKey = args[0];
        privateKey = args[1];
        console.error('Using API keys from command line arguments');
      } else {
        throw new Error('ATLAS_PUBLIC_KEY and ATLAS_PRIVATE_KEY must be provided either as environment variables or as command line arguments');
      }
    }

    this.apiKey = apiKey;
    this.privateKey = privateKey;

    this.setupToolHandlers();

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
          name: 'create_atlas_cluster',
          description: 'Creates a new Atlas cluster in an existing Atlas project.',
          inputSchema: {
            type: 'object',
            properties: {
              projectId: {
                type: 'string',
                description: 'The ID of the Atlas project.',
              },
              clusterName: {
                type: 'string',
                description: 'The name of the cluster to create.',
              },
              region: {
                type: 'string',
                description: 'The cloud provider region to deploy the cluster in. eg. US_EAST_1',
              },
              cloudProvider: {
                type: 'string',
                description: 'The cloud provider (e.g., AWS, GCP, AZURE).',
              },
              tier: {
                type: 'string',
                description: 'The instance size (e.g., M0, M2, M5).',
              }
            },
            required: ['projectId', 'clusterName', 'region', 'cloudProvider', 'tier'],
          },
        },
        {
          name: 'setup_atlas_network_access',
          description: 'Sets up network access for an existing Atlas project. Accepts list of IP addresses or CIDR blocks.',
          inputSchema: {
            type: 'object',
            properties: {
              projectId: {
                type: 'string',
                description: 'The ID of the Atlas project.',
              },
              ipAddresses: {
                type: 'array',
                items: {
                  type: 'string',
                },
                description: 'An array of IP addresses or CIDR blocks for network access.',
              },
            },
            required: ['projectId', 'ipAddresses'],
          },
        },
        {
          name: 'create_atlas_user',
          description: 'Creates a new database user for an existing Atlas project. User will have atlasAdmin role.',
          inputSchema: {
            type: 'object',
            properties: {
              projectId: {
                type: 'string',
                description: 'The ID of the Atlas project.',
              },
              username: {
                type: 'string',
                description: 'The username for the database user.',
              },
              password: {
                type: 'string',
                description: 'The password for the database user.',
              },
              roles: {
                type: 'array',
                items: {
                  type: 'string',
                },
                description: 'An array of roles for the user. Default is [atlasAdmin].',
              }
            },
            required: ['projectId', 'username', 'password'],
          },
        },
        {
          name: 'get_atlas_connection_strings',
          description: 'Retrieves connection strings for a cluster in an existing Atlas project.',
          inputSchema: {
            type: 'object',
            properties: {
              projectId: {
                type: 'string',
                description: 'The ID of the Atlas project.',
              },
              clusterName: {
                type: 'string',
                description: 'The name of the cluster.',
              },
            },
            required: ['projectId', 'clusterName'],
          },
        },
        {
          name: 'list_atlas_projects',
          description: 'Lists all Atlas projects that the API key has access to.',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'list_atlas_clusters',
          description: 'Lists all clusters in an Atlas project.',
          inputSchema: {
            type: 'object',
            properties: {
              projectId: {
                type: 'string',
                description: 'The ID of the Atlas project.',
              },
            },
            required: ['projectId'],
          },
        }
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      if (!['create_atlas_cluster', 'setup_atlas_network_access', 'create_atlas_user', 'get_atlas_connection_strings', 'list_atlas_projects', 'list_atlas_clusters'].includes(request.params.name)) {
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: ${request.params.name}`
        );
      }

      if (!request.params.arguments) {
        throw new McpError(ErrorCode.InvalidParams, 'Missing arguments');
      }

      const input = request.params.arguments as Record<string, unknown>;

      switch (request.params.name) {
        case 'create_atlas_cluster':
          if (!isValidCreateClusterInput(input)) {
            throw new McpError(ErrorCode.InvalidParams, 'Invalid cluster creation arguments');
          }
          break;
        case 'setup_atlas_network_access':
          if (!input.projectId || !input.ipAddresses || !Array.isArray(input.ipAddresses)) {
            throw new McpError(ErrorCode.InvalidParams, 'Invalid network access arguments');
          }
          break;
        case 'create_atlas_user':
          if (!input.projectId || !input.username || !input.password) {
            throw new McpError(ErrorCode.InvalidParams, 'Invalid user creation arguments');
          }
          break;
        case 'get_atlas_connection_strings':
          if (!input.projectId || !input.clusterName) {
            throw new McpError(ErrorCode.InvalidParams, 'Invalid connection string arguments');
          }
          break;
        case 'list_atlas_clusters':
          if (!input.projectId) {
            throw new McpError(ErrorCode.InvalidParams, 'Invalid list clusters arguments');
          }
          break;
      }

      let result;

      try {
        switch (request.params.name) {
          case 'create_atlas_cluster':
            result = await this.createAtlasCluster(input as unknown as CreateClusterInput);
            break;
          case 'setup_atlas_network_access':
            result = await this.setupAtlasNetworkAccess(input as unknown as NetworkAccessInput);
            break;
          case 'create_atlas_user':
            result = await this.createAtlasUser(input as unknown as CreateUserInput);
            break;
          case 'get_atlas_connection_strings':
            result = await this.getAtlasConnectionStrings(input as unknown as ConnectionStringsInput);
            break;
          case 'list_atlas_projects':
            result = await this.listAtlasProjects();
            break;
          case 'list_atlas_clusters':
            result = await this.listAtlasClusters(input as unknown as ListClustersInput);
            break;
          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
        }

        // Ensure we return the expected format
        return {
          content: result.content,
          _meta: request.params._meta
        };
      } catch (error: any) {
        // Handle any errors that might occur
        return {
          content: [{
            type: 'text',
            text: `Error: ${error.message}`
          }],
          isError: true,
          _meta: request.params._meta
        };
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Atlas Project Manager MCP server running on stdio');
  }
}

const server = new AtlasProjectManager();
server.run().catch(console.error);
