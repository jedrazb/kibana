/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { schema } from '@kbn/config-schema';
import { apiPrivileges } from '../../common/features';
import type { RouteDependencies } from './types';
import { getHandlerWrapper } from './wrap_handler';
import { KibanaMcpHttpTransport } from '../utils/kibana_mcp_http_transport';
import { ONECHAT_MCP_SERVER_UI_SETTING_ID } from '../../common/constants';
import { registerMCPOAuthRoutes } from './mcp_oauth';
import type { OnechatConfig } from '../config';

const TECHNICAL_PREVIEW_WARNING =
  'Elastic MCP Server is in technical preview and may be changed or removed in a future release. Elastic will work to fix any issues, but features in technical preview are not subject to the support SLA of official GA features.';

const MCP_SERVER_NAME = 'elastic-mcp-server';
const MCP_SERVER_VERSION = '0.0.1';
const MCP_SERVER_PATH = '/api/mcp';

// Helper function to validate OAuth token
async function validateOAuthToken(authHeader: string, logger: any): Promise<any> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.info(`OAuth token validation failed - no valid Bearer token`);
    return null;
  }

  try {
    const token = authHeader.substring(7);
    const tokenData = JSON.parse(Buffer.from(token, 'base64').toString());

    // Check if token is not too old (1 hour)
    if (Date.now() - tokenData.timestamp > 60 * 60 * 1000) {
      logger.info(`OAuth token validation failed - token expired`);
      return null;
    }

    // Verify GitHub token is still valid
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${tokenData.githubToken}`,
        'User-Agent': 'Kibana-MCP-Server',
      },
    });

    if (!userResponse.ok) {
      logger.info(`OAuth token validation failed - GitHub API returned ${userResponse.status}`);
      return null;
    }

    return tokenData;
  } catch (err) {
    logger.error('OAuth token validation error:', err);
    return null;
  }
}

export function registerMCPRoutes(
  { router, getInternalServices, logger, coreSetup }: RouteDependencies,
  config: OnechatConfig
) {
  const wrapHandler = getHandlerWrapper({ logger });

  // Register OAuth routes
  registerMCPOAuthRoutes({ router, getInternalServices, logger, coreSetup }, config);

  router.versioned
    .post({
      path: MCP_SERVER_PATH,
      security: {
        authz: {
          enabled: false,
          reason: 'This route supports both OAuth and internal Kibana auth',
        },
        authc: {
          enabled: false,
          reason: 'This route supports both OAuth and internal Kibana auth',
        },
      },
      access: 'public',
      summary: 'MCP server',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp'],
        xsrfRequired: false,
        availability: {
          stability: 'experimental',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: { body: schema.object({}, { unknowns: 'allow' }) },
        },
      },
      wrapHandler(async (ctx, request, response) => {
        let transport: KibanaMcpHttpTransport | undefined;
        let server: McpServer | undefined;

        // Check for OAuth authorization first
        const authHeader = request.headers.authorization as string;
        const oauthUser = await validateOAuthToken(authHeader, logger);

        if (!oauthUser) {
          // Fall back to original behavior if no OAuth token
          const { uiSettings } = await ctx.core;
          const enabled = await uiSettings.client.get(ONECHAT_MCP_SERVER_UI_SETTING_ID);

          if (!enabled) {
            logger.info(`MCP server request rejected - server not enabled`);
            return response.notFound();
          }
          logger.info(`MCP server request using internal auth`);
        } else {
          logger.info(`OAuth authenticated user: ${oauthUser.username} (${oauthUser.userId})`);
        }

        try {
          logger.info(`Initializing MCP server and transport`);
          transport = new KibanaMcpHttpTransport({ sessionIdGenerator: undefined, logger });

          // Instantiate new MCP server upon every request, no session persistence
          server = new McpServer({
            name: MCP_SERVER_NAME,
            version: MCP_SERVER_VERSION,
          });

          const { tools: toolService } = getInternalServices();

          const registry = toolService.registry.asScopedPublicRegistry({ request });
          const tools = await registry.list({});
          logger.info(`MCP server initialized with ${tools.length} tools`);

          // Expose tools scoped to the request
          for (const tool of tools) {
            server.tool(
              tool.id,
              tool.description,
              tool.schema.shape,
              async (args: { [x: string]: any }) => {
                logger.info(`Executing MCP tool: ${tool.id}`);
                const toolResult = await tool.execute({ toolParams: args });
                return {
                  content: [{ type: 'text' as const, text: JSON.stringify(toolResult) }],
                };
              }
            );
          }

          request.events.aborted$.subscribe(async () => {
            logger.info(`MCP request aborted, cleaning up resources`);
            await transport?.close().catch((error) => {
              logger.error('MCP Server: Error closing transport', { error });
            });
            await server?.close().catch((error) => {
              logger.error('MCP Server: Error closing server', { error });
            });
          });

          await server.connect(transport);
          logger.info(`MCP server connected and ready to handle request`);

          return await transport.handleRequest(request, response);
        } catch (error) {
          logger.error('MCP Server: Error handling request', { error });
          try {
            await transport?.close();
          } catch (closeError) {
            logger.error('MCP Server: Error closing transport during error handling', {
              error: closeError,
            });
          }
          if (server) {
            try {
              await server.close();
            } catch (closeError) {
              logger.error('MCP Server: Error closing server during error handling', {
                error: closeError,
              });
            }
          }

          logger.error('MCP Server: Error handling request', { error });
          return response.customError({
            statusCode: 500,
            body: {
              message: `Internal server error: ${error}`,
              attributes: {
                code: ErrorCode.InternalError,
              },
            },
          });
        }
      })
    );

  router.versioned
    .get({
      path: MCP_SERVER_PATH,
      security: {
        authz: { requiredPrivileges: [apiPrivileges.readOnechat] },
      },
      access: 'public',
      summary: 'MCP server',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp'],
        availability: {
          stability: 'experimental',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: false,
      },
      wrapHandler(async (ctx, _, response) => {
        const { uiSettings } = await ctx.core;
        const enabled = await uiSettings.client.get(ONECHAT_MCP_SERVER_UI_SETTING_ID);

        if (!enabled) {
          logger.info(`MCP server GET request rejected - server not enabled`);
          return response.notFound();
        }
        logger.info(`MCP server GET request received - returning method not allowed`);
        return response.customError({
          statusCode: 405,
          body: {
            message: 'Method not allowed',
            attributes: {
              code: ErrorCode.ConnectionClosed,
            },
          },
        });
      })
    );

  router.versioned
    .delete({
      path: MCP_SERVER_PATH,
      security: {
        authz: { requiredPrivileges: [apiPrivileges.readOnechat] },
      },
      access: 'public',
      summary: 'MCP server',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp'],
        xsrfRequired: false,
        availability: {
          stability: 'experimental',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: false,
      },
      wrapHandler(async (ctx, _, response) => {
        const { uiSettings } = await ctx.core;
        const enabled = await uiSettings.client.get(ONECHAT_MCP_SERVER_UI_SETTING_ID);

        if (!enabled) {
          logger.info(`MCP server DELETE request rejected - server not enabled`);
          return response.notFound();
        }
        logger.info(`MCP server DELETE request received - returning method not allowed`);
        return response.customError({
          statusCode: 405,
          body: {
            message: 'Method not allowed',
            attributes: {
              code: ErrorCode.ConnectionClosed,
            },
          },
        });
      })
    );
}
