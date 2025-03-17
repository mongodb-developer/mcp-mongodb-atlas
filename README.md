# MongoDB Atlas MCP Server

An MCP (Model Context Protocol) server for managing MongoDB Atlas projects. This package provides tools for creating and managing MongoDB Atlas clusters, users, and network access through the MCP interface.


## Demo Video

[![MongoDB Atlas MCP Server Demo](https://img.youtube.com/vi/h8nmRsOGUew/0.jpg)](https://www.youtube.com/watch?v=h8nmRsOGUew)

Watch the demonstration video to see MongoDB Atlas MCP Server in action.

## Features

### MCP Tools

- `create_atlas_cluster` - Create a new MongoDB Atlas cluster in an existing project
- `setup_atlas_network_access` - Configure network access for an Atlas project
- `create_atlas_user` - Create a new database user with atlasAdmin role
- `get_atlas_connection_strings` - Retrieve connection strings for a cluster
- `list_atlas_projects` - List all Atlas projects accessible with the provided API key
- `list_atlas_clusters` - List all clusters in a specific Atlas project

## Installation

```bash
npm install mcp-mongodb-atlas
```

## Usage

### As a Command Line Tool

You can run the Atlas Project Manager directly from the command line:

```bash
# Using environment variables
export ATLAS_PUBLIC_KEY="your-public-key"
export ATLAS_PRIVATE_KEY="your-private-key"
npx mcp-mongodb-atlas

# Or passing keys as arguments
npx mcp-mongodb-atlas "your-public-key" "your-private-key"
```


### With Cline (VSCode Extension)

To use with Cline in VSCode, add the server config to your MCP settings file:

```json
{
  "mcpServers": {
    "atlas": {
      "command": "npx",
      "args": ["mcp-mongodb-atlas"],
      "env": {
        "ATLAS_PUBLIC_KEY": "your-public-key",
        "ATLAS_PRIVATE_KEY": "your-private-key"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

The MCP settings file is located at:
- macOS: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- Windows: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`
- Linux: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`

### With Cursor

To use with Cursor, go to "Cursor settings" > "MCP" in the settings and add a new server with the following configuration:

1. **Name**: `atlas` (or any name you prefer)
2. **Command**: `npx mcp-mongodb-atlas`
3. **Arguments**: provide your API keys as arguments
```bash
## Suggested Command
npx mcp-mongodb-atlas <public_key> <private_key>
```

Newer versions can set the `~/.cursor/mcp.json` file with:
```
{
  "mcpServers": {
    "atlas": {
      "command": "npx",
      "args": ["mcp-mongodb-atlas"],
      "env": {
        "ATLAS_PUBLIC_KEY": "your-public-key",
        "ATLAS_PRIVATE_KEY": "your-private-key"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

4. **Environment Variables** (Optional):
   - `ATLAS_PUBLIC_KEY`: Your MongoDB Atlas public key
   - `ATLAS_PRIVATE_KEY`: Your MongoDB Atlas private key

### With Claude Desktop

To use with Claude Desktop, add the server config:

On macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
On Windows: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "atlas": {
      "command": "npx",
      "args": ["mcp-mongodb-atlas"],
      "env": {
        "ATLAS_PUBLIC_KEY": "your-public-key",
        "ATLAS_PRIVATE_KEY": "your-private-key"
      }
    }
  }
}
```

## API Keys

You need MongoDB Atlas API keys to use this tool. To create API keys:

1. Log in to your MongoDB Atlas account
2. Go to Access Manager > API Keys
3. Create a new API key with the appropriate permissions
4. Save the public and private keys

## Development

Clone the repository and install dependencies:

```bash
git clone https://github.com/mongodb-developer/mcp-mongodb-atlas.git
cd mcp-mongodb-atlas
npm install
```

Build the project:

```bash
npm run build
```

For development with auto-rebuild:

```bash
npm run watch
```

### Debugging

Since MCP servers communicate over stdio, debugging can be challenging. We recommend using the MCP Inspector:

```bash
npm run inspector
```

The Inspector will provide a URL to access debugging tools in your browser.

## License

MIT
