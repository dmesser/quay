import React, {useState} from 'react';
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  ClipboardCopy,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Divider,
  Flex,
  FlexItem,
  Grid,
  GridItem,
  Label,
  LabelGroup,
  PageSection,
  Spinner,
  Split,
  SplitItem,
  Stack,
  StackItem,
  Tab,
  Tabs,
  TabTitleText,
  Title,
  Tooltip,
} from '@patternfly/react-core';
import {
  CodeIcon,
  CopyIcon,
  CubeIcon,
  DownloadIcon,
  ExternalLinkAltIcon,
  GithubIcon,
  PlayIcon,
  ShieldAltIcon,
} from '@patternfly/react-icons';
import {Table, Thead, Tbody, Tr, Th, Td} from '@patternfly/react-table';
import prettyBytes from 'pretty-bytes';
import {useQuayConfig} from 'src/hooks/UseQuayConfig';
import {useHelmChartMetadata, useHelmIcon} from 'src/hooks/UseHelmChart';
import HelmChartReadme from './HelmChartReadme';
import HelmChartValuesTab from './HelmChartValuesTab';
import HelmChartFilesTab from './HelmChartFilesTab';
import HelmChartProvenanceModal from './HelmChartProvenanceModal';

function CopyableCell({text}: {text: string}) {
  const [hovered, setHovered] = useState(false);
  const [copied, setCopied] = useState(false);

  return (
    <Td
      style={{wordBreak: 'break-all'}}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => {
        setHovered(false);
        setCopied(false);
      }}
    >
      <span style={{display: 'inline-flex', alignItems: 'center', gap: '4px'}}>
        {text}
        <span style={{visibility: hovered ? 'visible' : 'hidden'}}>
          <Tooltip
            content={copied ? 'Copied!' : 'Copy'}
            position="top"
            entryDelay={0}
          >
            <Button
              icon={<CopyIcon />}
              variant="plain"
              size="sm"
              aria-label={`Copy ${text} to clipboard`}
              onClick={() => {
                navigator.clipboard.writeText(text);
                setCopied(true);
              }}
              style={{padding: 0}}
            />
          </Tooltip>
        </span>
      </span>
    </Td>
  );
}

type ContentTab = 'readme' | 'values' | 'files' | 'deps';

interface ParsedImageRef {
  registry: string;
  path: string; // "org/repo" or "org/repo/sub"
  tag?: string;
  digest?: string;
}

function parseImageRef(image: string): ParsedImageRef | null {
  const digestIdx = image.indexOf('@');
  const colonIdx = image.lastIndexOf(':');
  let main = image;
  let tag: string | undefined;
  let digest: string | undefined;

  if (digestIdx > 0) {
    digest = image.slice(digestIdx + 1);
    main = image.slice(0, digestIdx);
  } else if (colonIdx > 0) {
    const afterColon = image.slice(colonIdx + 1);
    if (!afterColon.includes('/')) {
      tag = afterColon;
      main = image.slice(0, colonIdx);
    }
  }

  const slashIdx = main.indexOf('/');
  if (slashIdx < 0) return null;

  const firstPart = main.slice(0, slashIdx);
  const hasPort = firstPart.includes(':');
  const hasDot = firstPart.includes('.');
  if (!hasDot && !hasPort) return null;

  return {
    registry: firstPart,
    path: main.slice(slashIdx + 1),
    tag,
    digest,
  };
}

function imageRefToLink(
  parsed: ParsedImageRef,
  quayDomain: string,
): {href: string; external: boolean} | null {
  const reg = parsed.registry.toLowerCase().replace(/:443$/, '');
  const quay = quayDomain.toLowerCase().replace(/:443$/, '');

  const isLocal = reg === quay;
  const isQuayIo = reg === 'quay.io';

  if (!isLocal && !isQuayIo) return null;

  const pathParts = parsed.path.split('/');
  if (pathParts.length < 2) return null;

  const org = pathParts[0];
  const repo = pathParts.slice(1).join('/');

  let repoPath: string;
  if (parsed.tag) {
    repoPath = `/repository/${org}/${repo}/tag/${parsed.tag}`;
  } else {
    repoPath = `/repository/${org}/${repo}`;
  }

  if (isQuayIo && !isLocal) {
    return {href: `https://quay.io${repoPath}`, external: true};
  }

  return {href: repoPath, external: false};
}

export default function HelmChartView(props: HelmChartViewProps) {
  const config = useQuayConfig();
  const domain = config?.config?.SERVER_HOSTNAME || window.location.host;

  const {
    data: metadata,
    isLoading,
    isError,
  } = useHelmChartMetadata(props.org, props.repo, props.digest);
  const {data: iconData} = useHelmIcon(props.org, props.repo, props.digest);

  const [activeTab, setActiveTab] = useState<ContentTab>('readme');
  const [provOpen, setProvOpen] = useState(false);

  if (isLoading) {
    return (
      <PageSection hasBodyWrapper={false}>
        <Spinner size="lg" aria-label="Loading Helm chart metadata" />
      </PageSection>
    );
  }

  if (isError || !metadata) {
    return (
      <PageSection hasBodyWrapper={false}>
        <Alert variant="danger" title="Failed to load Helm chart metadata" />
      </PageSection>
    );
  }

  if (metadata.extraction_status === 'pending') {
    return (
      <PageSection hasBodyWrapper={false}>
        <Alert
          variant="info"
          title="Helm chart metadata is being extracted"
          data-testid="helm-pending-alert"
        >
          Metadata extraction is in progress. This page will show chart details
          once processing is complete.
        </Alert>
      </PageSection>
    );
  }

  if (metadata.extraction_status === 'failed') {
    return (
      <PageSection hasBodyWrapper={false}>
        <Alert
          variant="warning"
          title="Helm chart metadata extraction failed"
          data-testid="helm-failed-alert"
        >
          {metadata.extraction_error ||
            'An unknown error occurred during extraction.'}
        </Alert>
      </PageSection>
    );
  }

  const m = metadata;
  const version = m.chart_version || '';
  const hasFiles = m.file_tree && m.file_tree.length > 0;
  const hasDeps = m.dependencies && m.dependencies.length > 0;

  const pullCmd = `helm pull oci://${domain}/${props.org}/${props.repo} --version ${version}`;
  const installCmd = `helm install ${
    m.chart_name || 'release-name'
  } oci://${domain}/${props.org}/${props.repo} --version ${version}`;

  const sidebar = (
    <Stack hasGutter data-testid="helm-chart-sidebar">
      <StackItem>
        <Card isCompact>
          <CardTitle>About</CardTitle>
          <CardBody>
            <DescriptionList isCompact>
              {m.api_version && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Chart API</DescriptionListTerm>
                  <DescriptionListDescription>
                    {m.api_version}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {version && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Chart version</DescriptionListTerm>
                  <DescriptionListDescription>
                    {version}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {m.app_version && (
                <DescriptionListGroup>
                  <DescriptionListTerm>App version</DescriptionListTerm>
                  <DescriptionListDescription>
                    {m.app_version}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {props.size != null && props.size > 0 && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Size</DescriptionListTerm>
                  <DescriptionListDescription>
                    {prettyBytes(props.size)}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {m.chart_type && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Type</DescriptionListTerm>
                  <DescriptionListDescription>
                    {m.chart_type}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              )}
              {m.kube_version && (
                <DescriptionListGroup>
                  <DescriptionListTerm>Kubernetes</DescriptionListTerm>
                  <DescriptionListDescription>
                    {m.kube_version}
                  </DescriptionListDescription>
                </DescriptionListGroup>
              )}
            </DescriptionList>
          </CardBody>
        </Card>
      </StackItem>

      {(m.home || (m.sources && m.sources.length > 0) || m.has_provenance) && (
        <StackItem>
          <Card isCompact>
            <CardTitle>Links</CardTitle>
            <CardBody>
              <Flex
                direction={{default: 'column'}}
                spaceItems={{default: 'spaceItemsXs'}}
              >
                {m.home && (
                  <FlexItem>
                    <a href={m.home} target="_blank" rel="noopener noreferrer">
                      <ExternalLinkAltIcon style={{marginRight: '6px'}} />
                      Homepage
                    </a>
                  </FlexItem>
                )}
                {m.sources?.map((src) => (
                  <FlexItem key={src}>
                    <a href={src} target="_blank" rel="noopener noreferrer">
                      <GithubIcon style={{marginRight: '6px'}} />
                      Source
                    </a>
                  </FlexItem>
                ))}
                {m.has_provenance && (
                  <FlexItem>
                    <Button
                      variant="link"
                      isInline
                      onClick={() => setProvOpen(true)}
                      data-testid="helm-provenance-link"
                      style={{paddingLeft: 0}}
                    >
                      <CodeIcon style={{marginRight: '6px'}} />
                      Provenance
                    </Button>
                  </FlexItem>
                )}
              </Flex>
            </CardBody>
          </Card>
        </StackItem>
      )}

      {(m.provenance_key_id ||
        m.provenance_hash_algorithm ||
        m.provenance_signature_date) && (
        <StackItem>
          <Card isCompact>
            <CardTitle>Provenance</CardTitle>
            <CardBody>
              <DescriptionList isCompact>
                {m.provenance_key_id && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Key ID</DescriptionListTerm>
                    <DescriptionListDescription
                      style={{
                        fontFamily: 'var(--pf-t--global--font--family--mono)',
                      }}
                    >
                      {m.provenance_key_id}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {m.provenance_hash_algorithm && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Hash algorithm</DescriptionListTerm>
                    <DescriptionListDescription>
                      {m.provenance_hash_algorithm}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
                {m.provenance_signature_date && (
                  <DescriptionListGroup>
                    <DescriptionListTerm>Signed</DescriptionListTerm>
                    <DescriptionListDescription>
                      {new Date(m.provenance_signature_date).toLocaleString()}
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                )}
              </DescriptionList>
            </CardBody>
          </Card>
        </StackItem>
      )}

      {m.maintainers && m.maintainers.length > 0 && (
        <StackItem>
          <Card isCompact>
            <CardTitle>Maintainers</CardTitle>
            <CardBody>
              {m.maintainers.map((maint) => (
                <div
                  key={maint.name}
                  style={{
                    fontSize: 'var(--pf-t--global--font--size--sm)',
                    marginBottom: '2px',
                  }}
                >
                  {maint.url ? (
                    <a
                      href={maint.url}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {maint.name}
                    </a>
                  ) : (
                    maint.name
                  )}
                  {maint.email && (
                    <span
                      style={{
                        color: 'var(--pf-t--global--text--color--subtle)',
                      }}
                    >
                      {' '}
                      &lt;{maint.email}&gt;
                    </span>
                  )}
                </div>
              ))}
            </CardBody>
          </Card>
        </StackItem>
      )}

      {m.keywords && m.keywords.length > 0 && (
        <StackItem>
          <Card isCompact>
            <CardTitle>Tags</CardTitle>
            <CardBody>
              <LabelGroup numLabels={10}>
                {m.keywords.map((kw) => (
                  <Label key={kw} isCompact>
                    {kw}
                  </Label>
                ))}
              </LabelGroup>
            </CardBody>
          </Card>
        </StackItem>
      )}

      {m.image_references && m.image_references.length > 0 && (
        <StackItem>
          <Card isCompact>
            <CardTitle>Container images</CardTitle>
            <CardBody>
              {m.image_references.map((ref) => {
                const parsed = parseImageRef(ref.image);
                const link = parsed ? imageRefToLink(parsed, domain) : null;

                return (
                  <div
                    key={`${ref.image}-${ref.location}`}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '6px',
                      fontSize: 'var(--pf-t--global--font--size--sm)',
                      fontFamily: 'var(--pf-t--global--font--family--mono)',
                      marginBottom: '4px',
                      wordBreak: 'break-all',
                    }}
                  >
                    <CubeIcon
                      style={{
                        flexShrink: 0,
                        marginTop: '2px',
                        color: 'var(--pf-t--global--icon--color--subtle)',
                      }}
                    />
                    {link ? (
                      <a
                        href={link.href}
                        {...(link.external
                          ? {target: '_blank', rel: 'noopener noreferrer'}
                          : {})}
                      >
                        {ref.image}
                        {link.external && (
                          <ExternalLinkAltIcon
                            style={{marginLeft: '4px', fontSize: '0.85em'}}
                          />
                        )}
                      </a>
                    ) : (
                      ref.image
                    )}
                  </div>
                );
              })}
            </CardBody>
          </Card>
        </StackItem>
      )}
    </Stack>
  );

  return (
    <>
      {/* Header band */}
      <PageSection hasBodyWrapper={false} data-testid="helm-sidebar">
        <Split hasGutter style={{alignItems: 'center'}}>
          <SplitItem style={{flexShrink: 0}}>
            {iconData ? (
              <img
                src={`data:${iconData.media_type};base64,${iconData.icon_data}`}
                alt={`${m.chart_name} icon`}
                style={{
                  width: 64,
                  height: 64,
                  minWidth: 50,
                  minHeight: 50,
                  objectFit: 'contain',
                }}
                data-testid="helm-chart-icon"
              />
            ) : (
              <div
                style={{
                  width: 64,
                  height: 64,
                  minWidth: 50,
                  minHeight: 50,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: 'var(--pf-t--global--border--radius--small)',
                  background:
                    'var(--pf-t--global--background--color--secondary--default)',
                  fontSize: '28px',
                  fontWeight: 'bold',
                  color: 'var(--pf-t--global--text--color--subtle)',
                }}
              >
                {(m.chart_name || 'H').charAt(0).toUpperCase()}
              </div>
            )}
          </SplitItem>
          <SplitItem isFilled>
            <Flex
              direction={{default: 'column'}}
              spaceItems={{default: 'spaceItemsNone'}}
            >
              <FlexItem>
                <Flex
                  alignItems={{default: 'alignItemsCenter'}}
                  spaceItems={{default: 'spaceItemsSm'}}
                >
                  <FlexItem>
                    <Title
                      headingLevel="h2"
                      size="xl"
                      style={{margin: 0}}
                      data-testid="helm-chart-title"
                    >
                      {m.chart_name}
                    </Title>
                  </FlexItem>
                  {version && (
                    <FlexItem>
                      <Label isCompact color="blue">
                        v{version}
                      </Label>
                    </FlexItem>
                  )}
                  {m.has_provenance && (
                    <FlexItem>
                      <Tooltip content="Signed — provenance available">
                        <ShieldAltIcon
                          color="var(--pf-t--global--icon--color--brand--default)"
                          data-testid="helm-provenance-badge"
                        />
                      </Tooltip>
                    </FlexItem>
                  )}
                  {m.deprecated && (
                    <FlexItem>
                      <Label isCompact color="orange">
                        Deprecated
                      </Label>
                    </FlexItem>
                  )}
                </Flex>
              </FlexItem>
              {m.app_version && (
                <FlexItem>
                  <span
                    style={{
                      fontSize: 'var(--pf-t--global--font--size--sm)',
                      color: 'var(--pf-t--global--text--color--subtle)',
                    }}
                  >
                    App Version: {m.app_version}
                  </span>
                </FlexItem>
              )}
              {m.description && (
                <FlexItem>
                  <span
                    style={{
                      color: 'var(--pf-t--global--text--color--subtle)',
                    }}
                  >
                    {m.description}
                  </span>
                </FlexItem>
              )}
            </Flex>
          </SplitItem>
          <SplitItem style={{marginLeft: 'var(--pf-t--global--spacer--xl)'}}>
            <Flex
              direction={{default: 'column'}}
              spaceItems={{default: 'spaceItemsXs'}}
              style={{width: '600px'}}
            >
              <FlexItem>
                <Split style={{alignItems: 'center', gap: '8px'}}>
                  <SplitItem>
                    <DownloadIcon
                      style={{
                        color: 'var(--pf-t--global--icon--color--subtle)',
                      }}
                    />
                  </SplitItem>
                  <SplitItem isFilled>
                    <ClipboardCopy
                      isReadOnly
                      hoverTip="Copy"
                      clickTip="Copied"
                      data-testid="helm-pull-command"
                    >
                      {pullCmd}
                    </ClipboardCopy>
                  </SplitItem>
                </Split>
              </FlexItem>
              <FlexItem>
                <Split style={{alignItems: 'center', gap: '8px'}}>
                  <SplitItem>
                    <PlayIcon
                      style={{
                        color: 'var(--pf-t--global--icon--color--subtle)',
                      }}
                    />
                  </SplitItem>
                  <SplitItem isFilled>
                    <ClipboardCopy
                      isReadOnly
                      hoverTip="Copy"
                      clickTip="Copied"
                      data-testid="helm-install-command"
                    >
                      {installCmd}
                    </ClipboardCopy>
                  </SplitItem>
                </Split>
              </FlexItem>
            </Flex>
          </SplitItem>
        </Split>
      </PageSection>

      <Divider />

      {/* Main body: tabs with sidebar inside each panel */}
      <PageSection hasBodyWrapper={false}>
        <Tabs
          activeKey={activeTab}
          onSelect={(_e, key) => setActiveTab(key as ContentTab)}
          aria-label="Helm chart content"
        >
          <Tab eventKey="readme" title={<TabTitleText>Readme</TabTitleText>}>
            <div style={{paddingTop: 'var(--pf-t--global--spacer--md)'}}>
              <Grid hasGutter>
                <GridItem span={9}>
                  <Card>
                    <CardBody>
                      <HelmChartReadme
                        org={props.org}
                        repo={props.repo}
                        digest={props.digest}
                      />
                    </CardBody>
                  </Card>
                </GridItem>
                <GridItem span={3}>{sidebar}</GridItem>
              </Grid>
            </div>
          </Tab>
          {m.has_values && (
            <Tab
              eventKey="values"
              title={<TabTitleText>Values</TabTitleText>}
              data-testid="helm-values-link"
            >
              <div style={{paddingTop: 'var(--pf-t--global--spacer--md)'}}>
                <Grid hasGutter>
                  <GridItem span={9}>
                    <HelmChartValuesTab
                      org={props.org}
                      repo={props.repo}
                      digest={props.digest}
                    />
                  </GridItem>
                  <GridItem span={3}>{sidebar}</GridItem>
                </Grid>
              </div>
            </Tab>
          )}
          {hasFiles && (
            <Tab
              eventKey="files"
              title={<TabTitleText>Files</TabTitleText>}
              data-testid="helm-filetree-link"
            >
              <div style={{paddingTop: 'var(--pf-t--global--spacer--md)'}}>
                <Grid hasGutter>
                  <GridItem span={9}>
                    <HelmChartFilesTab fileTree={m.file_tree || []} />
                  </GridItem>
                  <GridItem span={3}>{sidebar}</GridItem>
                </Grid>
              </div>
            </Tab>
          )}
          {hasDeps && (
            <Tab
              eventKey="deps"
              title={<TabTitleText>Dependencies</TabTitleText>}
              data-testid="helm-deps-link"
            >
              <div style={{paddingTop: 'var(--pf-t--global--spacer--md)'}}>
                <Grid hasGutter>
                  <GridItem span={9}>
                    <Card>
                      <CardBody>
                        <Table
                          aria-label="Chart dependencies"
                          variant="compact"
                          data-testid="helm-deps-table"
                        >
                          <Thead>
                            <Tr>
                              <Th>Name</Th>
                              <Th>Version</Th>
                              <Th>Repository</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {m.dependencies.map((dep) => (
                              <Tr key={dep.name}>
                                <Td>{dep.name}</Td>
                                <Td>{dep.version}</Td>
                                {dep.repository ? (
                                  <CopyableCell text={dep.repository} />
                                ) : (
                                  <Td>N/A</Td>
                                )}
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      </CardBody>
                    </Card>
                  </GridItem>
                  <GridItem span={3}>{sidebar}</GridItem>
                </Grid>
              </div>
            </Tab>
          )}
        </Tabs>
      </PageSection>

      <HelmChartProvenanceModal
        isOpen={provOpen}
        onClose={() => setProvOpen(false)}
        org={props.org}
        repo={props.repo}
        digest={props.digest}
      />
    </>
  );
}

type HelmChartViewProps = {
  org: string;
  repo: string;
  digest: string;
  size?: number;
};
