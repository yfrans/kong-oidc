local M = {}
local utils = require("kong.plugins.oidc.utils")

local function shouldIgnoreRequest(patterns)
  if (patterns) then
    for _, pattern in ipairs(patterns) do
      local isMatching = not (string.find(ngx.var.uri, pattern) == nil)
      if (isMatching) then return true end
    end
  end
  return false
end

function M.shouldProcessRequest(config)
  -- Handle WebSocket connections specially
  if utils.is_websocket_request() then
    if config.websocket_auth == "yes" then
      ngx.log(ngx.DEBUG, "OidcHandler processing WebSocket request with token validation")
      return true
    else
      ngx.log(ngx.DEBUG, "OidcHandler skipping WebSocket request")
      return false
    end
  end
  
  return not shouldIgnoreRequest(config.filters)
end

return M
