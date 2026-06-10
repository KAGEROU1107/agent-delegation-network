/**
 * Terminal 3 ADK authentication layer.
 * Uses the official @terminal3/t3n-sdk to perform real T3N auth.
 *
 * Key insight: T3N_API_KEY is an Ethereum private key.
 * eth_get_address(key) derives the address.
 * metamask_sign(address, undefined, key) signs offline — no browser needed.
 * The DID returned by authenticate() is the real, registered tenant DID.
 */

import {
  T3nClient,
  TenantClient,
  setEnvironment,
  loadWasmComponent,
  eth_get_address,
  metamask_sign,
  createDefaultHandlers,
  createEthAuthInput,
  getNodeUrl,
} from "@terminal3/t3n-sdk";

export interface T3nSession {
  t3n: T3nClient;
  tenant: TenantClient;
  /** Real DID from authenticated session — NOT hardcoded. */
  tenantDid: string;
  address: string;
}

/**
 * Authenticate with the Terminal 3 testnet using an Ethereum private key.
 * Returns the authenticated session including the real tenant DID.
 */
export async function createT3nSession(apiKey: string): Promise<T3nSession> {
  setEnvironment("testnet");

  const nodeUrl = getNodeUrl();
  const wasmComponent = await loadWasmComponent();
  const address = eth_get_address(apiKey);

  const t3n = new T3nClient({
    baseUrl: nodeUrl,
    wasmComponent,
    handlers: {
      ...createDefaultHandlers(nodeUrl),
      EthSign: metamask_sign(address, undefined, apiKey),
    },
  });

  await t3n.handshake();
  const didResult = await t3n.authenticate(createEthAuthInput(address));
  const tenantDid = didResult.value;

  const tenant = new TenantClient({
    t3n,
    baseUrl: getNodeUrl(),
    tenantDid,
  });

  return { t3n, tenant, tenantDid, address };
}
