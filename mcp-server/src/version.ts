/**
 * The server's own version, read from its package.json.
 *
 * Previously hardcoded as '0.5.0' in six places while the package shipped
 * 0.5.6, so `7h3_mcp_config` and the claude-code scaffold handed users an
 * install config pinned to a stale release. Deriving it means a release bump
 * cannot desync them again.
 */

import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const pkg = require('../package.json') as { version: string }

export const MCP_VERSION: string = pkg.version

/** The npm spec used in generated install configs, e.g. `@7h3/protocol-mcp@0.5.6`. */
export const MCP_PACKAGE_SPEC = `@7h3/protocol-mcp@${MCP_VERSION}`
