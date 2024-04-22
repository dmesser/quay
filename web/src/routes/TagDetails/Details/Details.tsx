import {
  ClipboardCopy,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Divider,
  PageSection,
  PageSectionVariants,
  Popover,
  Skeleton,
} from '@patternfly/react-core';
import {OutlinedQuestionCircleIcon} from '@patternfly/react-icons';
import {ImageSize} from 'src/components/Table/ImageSize';
import Labels from 'src/components/labels/Labels';
import {useFetchManifest} from 'src/hooks/UseManifest';
import {formatDate} from 'src/libs/utils';
import {Tag} from 'src/resources/TagResource';
import SecurityDetails from 'src/routes/RepositoryDetails/Tags/SecurityDetails';
import CopyTags from './DetailsCopyTags';

export default function Details(props: DetailsProps) {
  const {manifest, isLoading, isError} = useFetchManifest(
    props.org,
    props.repo,
    props.digest,
  );

  return (
    <>
      <PageSection variant={PageSectionVariants.light}>
        <DescriptionList
          columnModifier={{
            default: '2Col',
          }}
          data-testid="tag-details"
        >
          <DescriptionListGroup data-testid="name">
            <DescriptionListTerm>Name</DescriptionListTerm>
            <DescriptionListDescription>
              {props.tag.name ? (
                props.tag.name
              ) : (
                <Skeleton width="100%"></Skeleton>
              )}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup data-testid="creation">
            <DescriptionListTerm>
              Build date{' '}
              <Popover
                aria-label="Build date popover"
                headerContent={<div>Manifest Build date</div>}
                bodyContent={
                  <div>
                    The date on which this manifest was built (only available
                    for Docker and OCI images).
                  </div>
                }
              >
                <OutlinedQuestionCircleIcon style={{cursor: 'pointer'}} />
              </Popover>
            </DescriptionListTerm>
            <DescriptionListDescription>
              {!isLoading && !isError ? (
                formatDate(manifest.created)
              ) : (
                <Skeleton width="100%"></Skeleton>
              )}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup data-testid="repository">
            <DescriptionListTerm>Repository</DescriptionListTerm>
            <DescriptionListDescription>
              {props.repo ? props.repo : <Skeleton width="100%"></Skeleton>}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup data-testid="pushed">
            <DescriptionListTerm>
              Push date{' '}
              <Popover
                aria-label="Push date popover"
                headerContent={<div>Tag Push date</div>}
                bodyContent={
                  <div>
                    The date on which this tag was first seen by the registry.
                  </div>
                }
              >
                <OutlinedQuestionCircleIcon style={{cursor: 'pointer'}} />
              </Popover>
            </DescriptionListTerm>
            <DescriptionListDescription>
              {props.tag.pushed ? (
                formatDate(props.tag.pushed)
              ) : (
                <Skeleton width="100%"></Skeleton>
              )}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup>
            <DescriptionListTerm>Digest</DescriptionListTerm>
            <DescriptionListDescription>
              {props.digest ? (
                <ClipboardCopy
                  data-testid="digest-clipboardcopy"
                  isReadOnly
                  hoverTip="Copy"
                  clickTip="Copied"
                  variant="inline-compact"
                >
                  {props.digest}
                </ClipboardCopy>
              ) : (
                <Skeleton width="100%"></Skeleton>
              )}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup data-testid="size">
            <DescriptionListTerm>Size</DescriptionListTerm>
            <DescriptionListDescription>
              {props.digest != '' ? (
                <ImageSize
                  org={props.org}
                  repo={props.repo}
                  digest={props.digest}
                />
              ) : (
                <Skeleton width="100%"></Skeleton>
              )}
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup data-testid="vulnerabilities">
            <DescriptionListTerm>Vulnerabilities</DescriptionListTerm>
            <DescriptionListDescription>
              <SecurityDetails
                org={props.org}
                repo={props.repo}
                digest={props.digest}
                tag={props.tag.name}
                cacheResults={true}
              />
            </DescriptionListDescription>
          </DescriptionListGroup>
          <DescriptionListGroup data-testid="labels">
            <DescriptionListTerm>Labels</DescriptionListTerm>
            <DescriptionListDescription>
              {props.tag.manifest_digest !== '' ? (
                <Labels
                  org={props.org}
                  repo={props.repo}
                  digest={props.tag.manifest_digest}
                />
              ) : (
                <Skeleton width="100%"></Skeleton>
              )}
            </DescriptionListDescription>
          </DescriptionListGroup>
        </DescriptionList>
      </PageSection>
      <Divider />
      <PageSection variant={PageSectionVariants.light}>
        <CopyTags
          org={props.org}
          repo={props.repo}
          tag={props.tag.name}
          digest={props.digest}
        />
      </PageSection>
    </>
  );
}

type DetailsProps = {
  tag: Tag;
  org: string;
  repo: string;
  digest: string;
};
