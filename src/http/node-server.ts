import { createServer, type Server } from "node:http";
import {
  type NodePlatformHttpAdapterDependencies,
  writeNodePlatformHttpResponse,
} from "./node-adapter.js";

export type NodePlatformHttpServerDependencies =
  NodePlatformHttpAdapterDependencies;

export function createNodePlatformHttpServer(
  dependencies: NodePlatformHttpServerDependencies,
): Server {
  return createServer((request, response) => {
    void writeNodePlatformHttpResponse(dependencies, request, response)
      .catch(() => {
        writeSafeServerError(response);
      });
  });
}

function writeSafeServerError(response: {
  headersSent: boolean;
  statusCode: number;
  setHeader(name: string, value: string): void;
  end(body?: string): void;
}): void {
  if (response.headersSent) {
    response.end();
    return;
  }

  response.statusCode = 500;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(JSON.stringify({
    outcome: "error",
    message: "Request could not be completed.",
  }));
}
