import {useQuery} from '@tanstack/react-query';
import {
  getManifestByDigest,
  ManifestByDigestResponse,
} from 'src/resources/TagResource';

export function useFetchManifest(org: string, repo: string, digest: string) {
  const {data, isLoading, isError, error} = useQuery<ManifestByDigestResponse>(
    ['manifest', org, repo, digest],
    async () => {
      return getManifestByDigest(org, repo, digest);
    },
  );

  return {
    manifest: data,
    isLoading: isLoading,
    isError: isError,
    errorData: error,
  };
}
