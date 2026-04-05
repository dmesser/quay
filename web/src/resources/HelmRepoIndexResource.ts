import {AxiosResponse} from 'axios';
import axios from 'src/libs/axios';
import {assertHttpCode} from './ErrorHandling';

export interface HelmRepoIndexConfig {
  enabled: boolean;
  tagPattern: string | null;
}

export async function fetchHelmRepoIndexConfig(
  org: string,
  repo: string,
  signal: AbortSignal,
): Promise<HelmRepoIndexConfig> {
  const url = `/api/v1/repository/${org}/${repo}/helmrepo`;
  const response: AxiosResponse = await axios.get(url, {signal});
  assertHttpCode(response.status, 200);
  return response.data as HelmRepoIndexConfig;
}

export async function updateHelmRepoIndexConfig(
  org: string,
  repo: string,
  config: HelmRepoIndexConfig,
): Promise<HelmRepoIndexConfig> {
  const url = `/api/v1/repository/${org}/${repo}/helmrepo`;
  const response = await axios.put(url, config);
  assertHttpCode(response.status, 200);
  return response.data as HelmRepoIndexConfig;
}
