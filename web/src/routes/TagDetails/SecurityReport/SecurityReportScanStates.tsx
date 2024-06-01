import {
  Button,
  EmptyState,
  EmptyStateBody,
  EmptyStateFooter,
  EmptyStateHeader,
  EmptyStateIcon,
  Icon,
} from '@patternfly/react-core';
import {
  BanIcon,
  CheckIcon,
  ExclamationCircleIcon,
  PauseCircleIcon,
} from '@patternfly/react-icons';

export function QueuedState() {
  return (
    <EmptyState variant="full">
      <EmptyStateHeader
        titleText="Security scan is currently queued."
        icon={<EmptyStateIcon icon={PauseCircleIcon} />}
        headingLevel="h1"
      />
      <EmptyStateBody>Refresh page for updates in scan status.</EmptyStateBody>
      <EmptyStateFooter>
        <Button title="Home" onClick={() => window.location.reload()}>
          Reload
        </Button>
      </EmptyStateFooter>
    </EmptyState>
  );
}

export function FailedState() {
  const RedExclamationIcon = () => (
    <Icon size="lg">
      <ExclamationCircleIcon color="red" />
    </Icon>
  );
  return (
    <EmptyState variant="full">
      <EmptyStateHeader
        titleText="Security scan has failed."
        icon={<EmptyStateIcon icon={RedExclamationIcon} />}
        headingLevel="h1"
      />
      <EmptyStateBody>
        The scan could not be completed due to error.
      </EmptyStateBody>
    </EmptyState>
  );
}

export function UnsupportedState() {
  return (
    <EmptyState variant="full">
      <EmptyStateHeader
        titleText="Security scan is not supported."
        icon={<EmptyStateIcon icon={BanIcon} />}
        headingLevel="h1"
      />
      <EmptyStateBody>
        Image does not have content the scanner recognizes.
      </EmptyStateBody>
    </EmptyState>
  );
}

export function NoVulnerabilitiesState() {
  return (
    <EmptyState variant="full">
      <EmptyStateHeader
        titleText="No vulnerabilities found."
        icon={<EmptyStateIcon icon={CheckIcon} />}
        headingLevel="h1"
      />
      <EmptyStateBody>
        Image does not have any vulnerabilities the scanner could detect.
      </EmptyStateBody>
    </EmptyState>
  );
}
