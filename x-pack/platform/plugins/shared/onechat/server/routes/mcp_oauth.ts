/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { schema } from '@kbn/config-schema';
import type { RouteDependencies } from './types';
import { getHandlerWrapper } from './wrap_handler';
import type { OnechatConfig } from '../config';

const KIBANA_BASE_URL = process.env.KIBANA_BASE_URL || 'http://localhost:5601';

const TECHNICAL_PREVIEW_WARNING =
  'Elastic MCP OAuth Server is in technical preview and may be changed or removed in a future release.';

export function registerMCPOAuthRoutes(
  { router, logger }: RouteDependencies,
  config: OnechatConfig
) {
  const wrapHandler = getHandlerWrapper({ logger });

  const githubClientId = config.oauth?.github?.clientId;
  const githubClientSecret = config.oauth?.github?.clientSecret;

  if (!githubClientId || !githubClientSecret) {
    logger.warn(
      'GitHub OAuth not configured. OAuth routes will be disabled. Configure xpack.onechat.oauth.github.clientId and xpack.onechat.oauth.github.clientSecret'
    );
    return;
  }

  // OAuth Authorization Server Metadata Discovery
  router.versioned
    .get({
      path: '/.well-known/oauth-authorization-server',
      access: 'public',
      summary: 'OAuth Authorization Server Metadata',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp', 'oauth'],
        availability: {
          stability: 'experimental',
        },
      },
      security: {
        authz: {
          enabled: false,
          reason: 'Allow public access for OAuth discovery',
        },
        authc: {
          enabled: false,
          reason: 'Allow public access for OAuth discovery',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: false,
      },
      wrapHandler(async (ctx, request, response) => {
        const baseUrl = `${KIBANA_BASE_URL}`;
        logger.info(`OAuth metadata discovery request received`);

        return response.ok({
          body: {
            issuer: baseUrl,
            authorization_endpoint: `${baseUrl}/api/mcp/oauth/authorize`,
            token_endpoint: `${baseUrl}/api/mcp/oauth/token`,
            registration_endpoint: `${baseUrl}/api/mcp/oauth/register`,
            response_types_supported: ['code'],
            grant_types_supported: ['authorization_code'],
            code_challenge_methods_supported: ['S256'],
            scopes_supported: ['read'],
          },
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          },
        });
      })
    );

  // OAuth Authorization Endpoint - Redirect to GitHub
  router.versioned
    .get({
      path: '/api/mcp/oauth/authorize',
      access: 'public',
      summary: 'OAuth Authorization Endpoint',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp', 'oauth'],
        availability: {
          stability: 'experimental',
        },
      },
      security: {
        authz: {
          enabled: false,
          reason: 'Allow public access for OAuth authorization',
        },
        authc: {
          enabled: false,
          reason: 'Allow public access for OAuth authorization',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: {
            query: schema.object({
              client_id: schema.string(),
              redirect_uri: schema.string(),
              response_type: schema.string(),
              state: schema.maybe(schema.string()), // to make it work with mcp inspector see https://github.com/modelcontextprotocol/inspector/issues/442
              code_challenge: schema.maybe(schema.string()),
              code_challenge_method: schema.maybe(schema.string()),
              scope: schema.maybe(schema.string()),
            }),
          },
        },
      },
      wrapHandler(async (ctx, request, response) => {
        const { client_id, redirect_uri, state, code_challenge } = request.query;
        logger.info(
          `OAuth authorization request received - client_id: ${client_id}, redirect_uri: ${redirect_uri}`
        );

        // Store the MCP client details in session/state for callback
        const mcpState = Buffer.from(
          JSON.stringify({
            mcpClientId: client_id,
            mcpRedirectUri: redirect_uri,
            mcpState: state,
            codeChallenge: code_challenge,
          })
        ).toString('base64');

        // Redirect to GitHub OAuth
        const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
        githubAuthUrl.searchParams.set('client_id', githubClientId);
        githubAuthUrl.searchParams.set('redirect_uri', `${KIBANA_BASE_URL}/api/mcp/oauth/callback`);
        githubAuthUrl.searchParams.set('state', mcpState);
        githubAuthUrl.searchParams.set('scope', 'user:email');

        return response.redirected({
          headers: {
            location: githubAuthUrl.toString(),
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          },
        });
      })
    );

  // OAuth Callback - Handle GitHub callback and redirect back to MCP client
  router.versioned
    .get({
      path: '/api/mcp/oauth/callback',
      access: 'public',
      summary: 'OAuth Callback Endpoint',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp', 'oauth'],
        availability: {
          stability: 'experimental',
        },
      },
      security: {
        authz: {
          enabled: false,
          reason: 'Allow public access for OAuth callback',
        },
        authc: {
          enabled: false,
          reason: 'Allow public access for OAuth callback',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: {
            query: schema.object({
              code: schema.maybe(schema.string()),
              state: schema.maybe(schema.string()),
              error: schema.maybe(schema.string()),
            }),
          },
        },
      },
      wrapHandler(async (ctx, request, response) => {
        const { code, state, error } = request.query;
        logger.info(`OAuth callback received - error: ${error || 'none'}`);

        if (error) {
          return response.badRequest({
            body: {
              message: 'OAuth authorization failed',
              attributes: { error, code: 'oauth_authorization_failed' },
            },
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
        }

        try {
          // Decode the MCP state
          const mcpStateData = state
            ? JSON.parse(Buffer.from(state, 'base64').toString())
            : {
                mcpClientId: '',
                mcpRedirectUri: '',
                mcpState: undefined,
                codeChallenge: undefined,
              };

          // Exchange GitHub code for access token
          const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
              client_id: githubClientId,
              client_secret: githubClientSecret,
              code: code!,
            }),
          });

          const tokenData = await tokenResponse.json();

          if (tokenData.error) {
            throw new Error(tokenData.error_description || tokenData.error);
          }

          // Generate a temporary auth code for MCP client
          const mcpAuthCode = Buffer.from(
            JSON.stringify({
              githubToken: tokenData.access_token,
              timestamp: Date.now(),
            })
          ).toString('base64');

          // Redirect back to MCP client
          const redirectUrl = new URL(mcpStateData.mcpRedirectUri);
          redirectUrl.searchParams.set('code', mcpAuthCode);
          redirectUrl.searchParams.set('state', mcpStateData.mcpState);

          return response.redirected({
            headers: {
              location: redirectUrl.toString(),
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
        } catch (err) {
          logger.error('OAuth callback error:', err);
          return response.badRequest({
            body: {
              message: 'OAuth callback failed',
              attributes: { details: err.message, code: 'oauth_callback_failed' },
            },
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
        }
      })
    );

  // OAuth Token Endpoint - Exchange auth code for access token
  router.versioned
    .post({
      path: '/api/mcp/oauth/token',
      access: 'public',
      summary: 'OAuth Token Endpoint',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp', 'oauth'],
        xsrfRequired: false,
        availability: {
          stability: 'experimental',
        },
      },
      security: {
        authz: {
          enabled: false,
          reason: 'Allow public access for OAuth token exchange',
        },
        authc: {
          enabled: false,
          reason: 'Allow public access for OAuth token exchange',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: {
            body: schema.object({
              grant_type: schema.string(),
              code: schema.string(),
              client_id: schema.string(),
              code_verifier: schema.maybe(schema.string()),
              redirect_uri: schema.maybe(schema.string()),
            }),
          },
        },
      },
      wrapHandler(async (ctx, request, response) => {
        const { grant_type, code, client_id, code_verifier } = request.body;
        logger.info(
          `OAuth token exchange request received - grant_type: ${grant_type}, client_id: ${client_id}`
        );

        if (grant_type !== 'authorization_code') {
          return response.badRequest({
            body: {
              message: 'Unsupported grant type',
              attributes: { error: 'unsupported_grant_type', code: 'unsupported_grant_type' },
            },
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
        }

        try {
          // Decode the auth code to get GitHub token
          const authData = JSON.parse(Buffer.from(code, 'base64').toString());
          const { githubToken, timestamp } = authData;

          // Check if token is not too old (5 minutes)
          if (Date.now() - timestamp > 5 * 60 * 1000) {
            return response.badRequest({
              body: {
                message: 'Authorization code expired',
                attributes: { error: 'invalid_grant', code: 'invalid_grant' },
              },
              headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
              },
            });
          }

          // Verify GitHub token is valid by calling GitHub API
          const userResponse = await fetch('https://api.github.com/user', {
            headers: {
              Authorization: `Bearer ${githubToken}`,
              'User-Agent': 'Kibana-MCP-Server',
            },
          });

          if (!userResponse.ok) {
            throw new Error('Invalid GitHub token');
          }

          const userData = await userResponse.json();

          // Create MCP access token with user info
          const mcpAccessToken = Buffer.from(
            JSON.stringify({
              githubToken,
              userId: userData.id,
              username: userData.login,
              email: userData.email,
              timestamp: Date.now(),
            })
          ).toString('base64');

          return response.ok({
            body: {
              access_token: mcpAccessToken,
              token_type: 'Bearer',
              expires_in: 3600,
              scope: 'read',
            },
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
        } catch (err) {
          logger.error('Token exchange error:', err);
          return response.badRequest({
            body: {
              message: 'Failed to exchange authorization code',
              attributes: { error: 'invalid_grant', code: 'invalid_grant' },
            },
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
        }
      })
    );

  // Dynamic Client Registration (simplified for POC)
  router.versioned
    .post({
      path: '/api/mcp/oauth/register',
      access: 'public',
      summary: 'OAuth Dynamic Client Registration',
      description: TECHNICAL_PREVIEW_WARNING,
      options: {
        tags: ['mcp', 'oauth'],
        xsrfRequired: false,
        availability: {
          stability: 'experimental',
        },
      },
      security: {
        authz: {
          enabled: false,
          reason: 'Allow public access for OAuth client registration',
        },
        authc: {
          enabled: false,
          reason: 'Allow public access for OAuth client registration',
        },
      },
    })
    .addVersion(
      {
        version: '2023-10-31',
        validate: {
          request: {
            body: schema.object({
              redirect_uris: schema.arrayOf(schema.string()),
              client_name: schema.maybe(schema.string()),
              grant_types: schema.maybe(schema.arrayOf(schema.string())),
              response_types: schema.maybe(schema.arrayOf(schema.string())),
              token_endpoint_auth_method: schema.maybe(schema.string()),
              client_uri: schema.maybe(schema.string()),
              scope: schema.maybe(schema.string()),
            }),
          },
        },
      },
      wrapHandler(async (ctx, request, response) => {
        const { redirect_uris, client_name } = request.body;
        logger.info(
          `OAuth client registration request received - client_name: ${client_name}, redirect_uris: ${redirect_uris.join(
            ', '
          )}`
        );

        // For POC, generate a simple client ID
        const clientId = `mcp_client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        return response.ok({
          body: {
            client_id: clientId,
            client_name: client_name || 'MCP Client',
            redirect_uris,
            grant_types: ['authorization_code'],
            response_types: ['code'],
            token_endpoint_auth_method: 'none', // Public client
          },
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          },
        });
      })
    );
}
