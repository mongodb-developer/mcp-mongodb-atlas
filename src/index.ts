#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

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

  private async createAtlasCluster(input: CreateClusterInput) {
    if (input.tier === 'M0') {
      return {
        content: [
          {
            type: 'text',
            text: 'M0 (Free Tier) clusters cannot be created via the API. Please use the MongoDB Atlas UI to create an M0 cluster.'
          }
        ],
        isError: true
      };
    }

    try {
      const curlCommand = `curl --location --request POST 'https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/clusters?pretty=true' \\
        --user "${this.apiKey}:${this.privateKey}" --digest \\
        --header 'Content-Type: application/json' \\
        --data-raw '{
          "name": "${input.clusterName}",
          "providerSettings": {
            "providerName": "${input.cloudProvider}",
            "instanceSizeName": "${input.tier}",
            "regionName": "${input.region}"
          }
        }'`;

      const { stdout, stderr } = await execPromise(curlCommand);
      
      if (stderr) {
        console.error('Stderr:', stderr);
      }

      return {
        content: [
          {
            type: 'text',
            text: stdout
          }
        ]
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Atlas API error: ${error.message}`
          }
        ],
        isError: true
      };
    }
  }

  private async setupAtlasNetworkAccess(input: NetworkAccessInput) {
    try {
      // Create a JSON array of IP addresses
      const ipAddressesJson = JSON.stringify(input.ipAddresses.map(ip => ({
        ipAddress: ip,
        comment: "Added via Atlas Project Manager MCP"
      })));

      const curlCommand = `curl --location --request POST 'https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/accessList' \\
        --user "${this.apiKey}:${this.privateKey}" --digest \\
        --header 'Content-Type: application/json' \\
        --data-raw '${ipAddressesJson}'`;

      const { stdout, stderr } = await execPromise(curlCommand);
      
      if (stderr) {
        console.error('Stderr:', stderr);
      }

      return {
        content: [
          {
            type: 'text',
            text: stdout
          }
        ]
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Atlas API error: ${error.message}`
          }
        ],
        isError: true
      };
    }
  }

  private async createAtlasUser(input: CreateUserInput) {
    try {
      const roles = JSON.stringify(input.roles.map(role => ({ databaseName: 'admin', roleName: role })));
      const curlCommand = `curl --location --request POST 'https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/databaseUsers' \\
        --user "${this.apiKey}:${this.privateKey}" --digest \\
        --header 'Content-Type: application/json' \\
        --data-raw '{
          "databaseName": "admin",
          "username": "${input.username}",
          "password": "${input.password}",
          "roles": ${roles}
        }'`;

      const { stdout, stderr } = await execPromise(curlCommand);
      
      if (stderr) {
        console.error('Stderr:', stderr);
      }

      return {
        content: [
          {
            type: 'text',
            text: stdout
          }
        ]
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Atlas API error: ${error.message}`
          }
        ],
        isError: true
      };
    }
  }

  private async getAtlasConnectionStrings(input: ConnectionStringsInput) {
    try {
      const curlCommand = `curl --location --request GET 'https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/clusters/${input.clusterName}' \\
        --user "${this.apiKey}:${this.privateKey}" --digest`;

      const { stdout, stderr } = await execPromise(curlCommand);
      
      if (stderr) {
        console.error('Stderr:', stderr);
      }

      return {
        content: [
          {
            type: 'text',
            text: stdout
          }
        ]
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Atlas API error: ${error.message}`
          }
        ],
        isError: true
      };
    }
  }

  private async listAtlasProjects() {
    try {
      const curlCommand = `curl --location --request GET 'https://cloud.mongodb.com/api/atlas/v1.0/groups' \\
        --user "${this.apiKey}:${this.privateKey}" --digest`;

      const { stdout, stderr } = await execPromise(curlCommand);
      
      if (stderr) {
        console.error('Stderr:', stderr);
      }

      return {
        content: [
          {
            type: 'text',
            text: stdout
          }
        ]
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Atlas API error: ${error.message}`
          }
        ],
        isError: true
      };
    }
  }

  private async listAtlasClusters(input: ListClustersInput) {
    try {
      const curlCommand = `curl --location --request GET 'https://cloud.mongodb.com/api/atlas/v1.0/groups/${input.projectId}/clusters' \\
        --user "${this.apiKey}:${this.privateKey}" --digest`;

      const { stdout, stderr } = await execPromise(curlCommand);
      
      if (stderr) {
        console.error('Stderr:', stderr);
      }

      return {
        content: [
          {
            type: 'text',
            text: stdout
          }
        ]
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Atlas API error: ${error.message}`
          }
        ],
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

    // Try to get API keys from environment variables first
    let apiKey = process.env.ATLAS_PUBLIC_KEY;
    let privateKey = process.env.ATLAS_PRIVATE_KEY;

    // If environment variables are not set, try to get from command line arguments
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

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
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

      let content;

      switch (request.params.name) {
        case 'create_atlas_cluster':
          content = await this.createAtlasCluster(input as unknown as CreateClusterInput);
          break;
        case 'setup_atlas_network_access':
          content = await this.setupAtlasNetworkAccess(input as unknown as NetworkAccessInput);
          break;
        case 'create_atlas_user':
          content = await this.createAtlasUser(input as unknown as CreateUserInput);
          break;
        case 'get_atlas_connection_strings':
          content = await this.getAtlasConnectionStrings(input as unknown as ConnectionStringsInput);
          break;
        case 'list_atlas_projects':
          content = await this.listAtlasProjects();
          break;
        case 'list_atlas_clusters':
          content = await this.listAtlasClusters(input as unknown as ListClustersInput);
          break;
        default:
          throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${request.params.name}`);
      }

      return content;
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
