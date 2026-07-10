import { createServer } from "node:http";

import { handleNodePlatformHttpRequest } from "../../../dist/index.js";
import { createInMemoryPlatformRepositories } from "../../../tests/helpers/in-memory-platform-repositories.mjs";

const dependencies = {
  repositories: createInMemoryPlatformRepositories(),
  now: () => new Date().toISOString(),
  cookie: { secure: false },
  originConfig: { allowedOrigins: ["http://127.0.0.1:8765"] },
};

const server = createServer(async (request, response) => {
  const result = await handleNodePlatformHttpRequest(dependencies, {
    method: request.method,
    url: request.url,
    headers: request.headers,
  });

  response.writeHead(result.statusCode, result.headers);
  response.end(result.body);
});

server.listen(8765, "127.0.0.1", () => {
  console.log("baseline server listening on http://127.0.0.1:8765");
});

process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
});
