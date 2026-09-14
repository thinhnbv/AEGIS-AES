@echo off
set "CONFIG_FILE=%USERPROFILE%\.claude.json"
echo {"env":{"ANTHROPIC_API_KEY":"as_eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJwcm94eV9rZXkiLCJwcm9kdWN0SWQiOjYsImFjY291bnRUaW1lIjoiMSBtb250aCIsImlhdCI6MTc4ODE5MDM1MCwiZXhwIjoxNzkwNzgyMzUwfQ.pQOfEfXHb_x1X5OpYLjlXLF2tsVHu3T8V9HIBfWsRgSDU0xIEyXtwn5Dmr4YUol6y08VAfeOxsnx-NL7blochw","ANTHROPIC_AUTH_TOKEN":"as_eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJwcm94eV9rZXkiLCJwcm9kdWN0SWQiOjYsImFjY291bnRUaW1lIjoiMSBtb250aCIsImlhdCI6MTc4ODE5MDM1MCwiZXhwIjoxNzkwNzgyMzUwfQ.pQOfEfXHb_x1X5OpYLjlXLF2tsVHu3T8V9HIBfWsRgSDU0xIEyXtwn5Dmr4YUol6y08VAfeOxsnx-NL7blochw","ANTHROPIC_BASE_URL":"https://api.agentshop247.com/api/claude","ENABLE_TOOL_SEARCH":"false","API_TIMEOUT_MS":"3000000","BASH_MAX_TIMEOUT_MS":"500000","BASH_DEFAULT_TIMEOUT_MS":"30000","CLAUDE_ENABLE_STREAM_WATCHDOG":"true"}} > "%CONFIG_FILE%"
echo the configuration has been set up successfully.
claude
