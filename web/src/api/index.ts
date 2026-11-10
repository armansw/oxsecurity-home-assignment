import { GraphqlScanApi } from './graphql';
import { API_BASE } from './http';
import { RestScanApi } from './rest';
import type { ScanApi, Transport } from './types';

export function createScanApi(transport: Transport, base: string = API_BASE): ScanApi {
  return transport === 'rest' ? new RestScanApi(base) : new GraphqlScanApi(base);
}

export { ApiError } from './errors';
export type * from './types';
export { isTerminal, PAGE_SIZE } from './types';
