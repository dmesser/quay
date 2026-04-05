import {
  ActionGroup,
  Alert,
  Button,
  ClipboardCopy,
  Form,
  FormGroup,
  FormHelperText,
  HelperText,
  HelperTextItem,
  Spinner,
  Switch,
  TextInput,
  Title,
} from '@patternfly/react-core';
import React, {useEffect, useState} from 'react';
import {AlertVariant, useUI} from 'src/contexts/UIContext';
import {
  useHelmRepoIndexConfig,
  useUpdateHelmRepoIndexConfig,
} from 'src/hooks/UseHelmRepoIndex';
import {useQuayConfig} from 'src/hooks/UseQuayConfig';
import {getErrorMessageFromUnknown} from 'src/resources/ErrorHandling';
import RequestError from 'src/components/errors/RequestError';

export default function HelmRepoIndex(props: HelmRepoIndexProps) {
  const [enabled, setEnabled] = useState(false);
  const [tagPattern, setTagPattern] = useState('');
  const [patternError, setPatternError] = useState<string | null>(null);
  const [isDirty, setIsDirty] = useState(false);
  const {addAlert} = useUI();
  const config = useQuayConfig();

  const {
    config: indexConfig,
    isLoading,
    error: fetchError,
  } = useHelmRepoIndexConfig(props.org, props.repo);

  const {updateConfig, isUpdating} = useUpdateHelmRepoIndexConfig(
    props.org,
    props.repo,
    {
      onSuccess: () => {
        addAlert({
          title: 'Helm repository index configuration saved',
          variant: AlertVariant.Success,
        });
        setIsDirty(false);
        setPatternError(null);
      },
      onError: (error) => {
        const msg = getErrorMessageFromUnknown(error);
        if (
          msg.toLowerCase().includes('regex') ||
          msg.toLowerCase().includes('pattern')
        ) {
          setPatternError(msg);
        } else {
          addAlert({
            title: 'Failed to save Helm repository index configuration',
            variant: AlertVariant.Failure,
            message: msg,
          });
        }
      },
    },
  );

  useEffect(() => {
    if (indexConfig) {
      setEnabled(indexConfig.enabled);
      setTagPattern(indexConfig.tagPattern ?? '');
    }
  }, [indexConfig]);

  const validatePattern = (pattern: string): boolean => {
    if (!pattern.trim()) {
      setPatternError(null);
      return true;
    }
    if (pattern.length > 256) {
      setPatternError('Tag pattern must be 256 characters or less');
      return false;
    }
    setPatternError(null);
    return true;
  };

  const handleToggle = (
    _event: React.FormEvent<HTMLInputElement>,
    checked: boolean,
  ) => {
    setEnabled(checked);
    setIsDirty(true);
  };

  const handlePatternChange = (_event: React.FormEvent, value: string) => {
    setTagPattern(value);
    validatePattern(value);
    setIsDirty(true);
  };

  const handleSave = () => {
    if (!validatePattern(tagPattern)) return;
    updateConfig({
      enabled,
      tagPattern: tagPattern.trim() || null,
    });
  };

  if (isLoading) {
    return <Spinner />;
  }

  if (fetchError) {
    return <RequestError err={fetchError} />;
  }

  const serverHostname =
    config?.config?.SERVER_HOSTNAME ?? window.location.host;
  const repoUrl = `${window.location.protocol}//${serverHostname}/${props.org}/${props.repo}`;

  return (
    <>
      <Title headingLevel="h2" className="pf-v6-u-pb-sm">
        Helm Repository Index
      </Title>
      <p className="pf-v6-u-pb-md">
        Enable a standard Helm repository index so clients can discover and
        install charts from this repository using <code>helm repo add</code>.
        When enabled, Quay generates an <code>index.yaml</code> from all Helm
        chart tags in this repository.
      </p>

      <Alert
        variant="info"
        isInline
        title="Background processing"
        className="pf-v6-u-mb-md"
        data-testid="helm-index-info-alert"
      >
        Helm chart metadata is extracted asynchronously. After pushing a new
        chart, it may take a few moments before it appears in the index.
      </Alert>

      <Form>
        <FormGroup fieldId="helm-repo-index-toggle">
          <Switch
            id="helm-repo-index-toggle"
            label="Helm repository index enabled"
            isChecked={enabled}
            onChange={handleToggle}
            data-testid="helm-repo-index-toggle"
          />
        </FormGroup>

        {enabled && (
          <>
            <FormGroup
              label="Tag pattern (optional)"
              fieldId="helm-repo-index-tag-pattern"
            >
              <TextInput
                id="helm-repo-index-tag-pattern"
                value={tagPattern}
                onChange={handlePatternChange}
                placeholder="e.g. ^v[0-9]+\\..*"
                validated={patternError ? 'error' : 'default'}
                data-testid="helm-repo-index-tag-pattern"
              />
              <FormHelperText>
                <HelperText>
                  <HelperTextItem variant={patternError ? 'error' : 'default'}>
                    {patternError ??
                      'Optional regex to filter which tags are included. Leave empty to include all Helm chart tags.'}
                  </HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>

            <FormGroup label="Usage" fieldId="helm-repo-index-usage">
              <ClipboardCopy
                isReadOnly
                hoverTip="Copy"
                clickTip="Copied"
                data-testid="helm-repo-add-command"
              >
                {`helm repo add ${props.repo} ${repoUrl}`}
              </ClipboardCopy>
            </FormGroup>
          </>
        )}

        <ActionGroup>
          <Button
            variant="primary"
            onClick={handleSave}
            isDisabled={!isDirty || isUpdating || !!patternError}
            isLoading={isUpdating}
            data-testid="helm-repo-index-save-btn"
          >
            Save
          </Button>
        </ActionGroup>
      </Form>
    </>
  );
}

interface HelmRepoIndexProps {
  org: string;
  repo: string;
}
