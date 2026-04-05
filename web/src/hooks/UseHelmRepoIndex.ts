import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import {
  HelmRepoIndexConfig,
  fetchHelmRepoIndexConfig,
  updateHelmRepoIndexConfig,
} from 'src/resources/HelmRepoIndexResource';

export function useHelmRepoIndexConfig(
  org: string,
  repo: string,
  enabled = true,
) {
  const {
    data: config,
    isLoading,
    error,
  } = useQuery(
    ['helmRepoIndex', org, repo],
    ({signal}) => fetchHelmRepoIndexConfig(org, repo, signal),
    {enabled: enabled && !!org && !!repo},
  );

  return {config, isLoading, error};
}

export function useUpdateHelmRepoIndexConfig(
  org: string,
  repo: string,
  {
    onSuccess,
    onError,
  }: {onSuccess?: () => void; onError?: (error: unknown) => void},
) {
  const queryClient = useQueryClient();
  const {mutate: updateConfig, isLoading: isUpdating} = useMutation(
    async (config: HelmRepoIndexConfig) =>
      updateHelmRepoIndexConfig(org, repo, config),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['helmRepoIndex', org, repo]);
        onSuccess?.();
      },
      onError: (error: unknown) => {
        onError?.(error);
      },
    },
  );

  return {updateConfig, isUpdating};
}
