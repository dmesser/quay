import axios, {AxiosResponse} from 'axios';
import {assertHttpCode} from './ErrorHandling';

export interface Data {
  Layer: Layer;
}
export interface Layer {
  Name: string;
  ParentName: string;
  NamespaceName: string;
  IndexedByVersion: number;
  Features: Feature[];
}

export interface Feature {
  Name: string;
  VersionFormat: string;
  NamespaceName: string;
  AddedBy: string;
  Version: string;
  Vulnerabilities?: Vulnerability[];
}

export interface Vulnerability {
  Severity: VulnerabilitySeverity;
  NamespaceName: string;
  Link: string;
  FixedBy: string;
  Description: string;
  Name: string;
  Metadata: VulnerabilityMetadata;
}

export interface VulnerabilityMetadata {
  UpdatedBy: string;
  RepoName: string;
  RepoLink: string;
  DistroName: string;
  DistroVersion: string;
  NVD: {
    CVSSv3: {
      Vectors: string;
      Score: number;
    };
  };
}

export enum VulnerabilitySeverity {
  Critical = 'Critical',
  High = 'High',
  Medium = 'Medium',
  Low = 'Low',
  Negligible = 'Negligible',
  None = 'None',
  Unknown = 'Unknown',
}

export const VulnerabilityOrder = {
  [VulnerabilitySeverity.Critical]: 0,
  [VulnerabilitySeverity.High]: 1,
  [VulnerabilitySeverity.Medium]: 2,
  [VulnerabilitySeverity.Low]: 3,
  [VulnerabilitySeverity.Negligible]: 4,
  [VulnerabilitySeverity.Unknown]: 5,
};

export interface SecurityDetailsResponse {
  status: string;
  data: Data;
}

export interface SecuritySummaryResponse {
  status: string;
  data: Map<VulnerabilitySeverity, number>;
}

export async function fetchSecurityDetails(
  org: string,
  repo: string,
  digest: string,
  fetchVulnerabilities = true,
  signal: AbortSignal,
) {
  const response: AxiosResponse<SecurityDetailsResponse> = await axios.get(
    `/api/v1/repository/${org}/${repo}/manifest/${digest}/security` +
      (fetchVulnerabilities ? '?vulnerabilities=true' : ''),
    {signal},
  );
  assertHttpCode(response.status, 200);
  return response.data as SecurityDetailsResponse;
}

export async function fetchSecuritySummary(
  org: string,
  repo: string,
  digest: string,
  signal: AbortSignal,
) {
  const response: AxiosResponse<SecuritySummaryResponse> = await axios.get(
    `/api/v1/repository/${org}/${repo}/manifest/${digest}/securitysummary`,
    {signal},
  );
  assertHttpCode(response.status, 200);

  const severityMap = new Map<VulnerabilitySeverity, number>();
  for (const key in response.data.data) {
    severityMap.set(key as VulnerabilitySeverity, response.data.data[key]);
  }

  return {status: response.data.status, data: severityMap};
}
