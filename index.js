import { KerliixClient } from "./lib/client.js";
import * as middleware from "./lib/middleware.js";

export function kerliixClient(config) {
  return new KerliixClient(config);
}

export { middleware };
