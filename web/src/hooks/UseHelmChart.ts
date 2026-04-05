import {useQuery} from '@tanstack/react-query';
import {
  getHelmChartMetadata,
  getHelmReadme,
  getHelmValues,
  getHelmSchema,
  getHelmIcon,
  getHelmProvenance,
} from 'src/resources/TagResource';

export function useHelmChartMetadata(
  org: string,
  repo: string,
  digest: string,
) {
  return useQuery(
    ['helmChartMetadata', org, repo, digest],
    () => getHelmChartMetadata(org, repo, digest),
    {
      enabled: !!org && !!repo && !!digest,
      retry: 1,
    },
  );
}

export function useHelmReadme(org: string, repo: string, digest: string) {
  return useQuery(
    ['helmReadme', org, repo, digest],
    () => getHelmReadme(org, repo, digest),
    {
      enabled: !!org && !!repo && !!digest,
      retry: false,
    },
  );
}

export function useHelmValues(org: string, repo: string, digest: string) {
  return useQuery(
    ['helmValues', org, repo, digest],
    () => getHelmValues(org, repo, digest),
    {
      enabled: !!org && !!repo && !!digest,
      retry: false,
    },
  );
}

export function useHelmSchema(org: string, repo: string, digest: string) {
  return useQuery(
    ['helmSchema', org, repo, digest],
    () => getHelmSchema(org, repo, digest),
    {
      enabled: !!org && !!repo && !!digest,
      retry: false,
    },
  );
}

export function useHelmIcon(org: string, repo: string, digest: string) {
  return useQuery(
    ['helmIcon', org, repo, digest],
    () => getHelmIcon(org, repo, digest),
    {
      enabled: !!org && !!repo && !!digest,
      retry: false,
    },
  );
}

export function useHelmProvenance(org: string, repo: string, digest: string) {
  return useQuery(
    ['helmProvenance', org, repo, digest],
    () => getHelmProvenance(org, repo, digest),
    {
      enabled: !!org && !!repo && !!digest,
      retry: false,
    },
  );
}
