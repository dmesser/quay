import RequestError from 'src/components/errors/RequestError';
import {useManifestSecurity} from 'src/hooks/UseManifestSecurity';
import {addDisplayError} from 'src/resources/ErrorHandling';
import {
  FailedState,
  QueuedState,
  UnsupportedState,
} from 'src/routes/TagDetails/SecurityReport/SecurityReportScanStates';
import {PackagesChart} from './PackagesChart';
import PackagesTable from './PackagesTable';

export interface PackageReportProps {
  org: string;
  repo: string;
  digest: string;
  load?: boolean;
}

Packages.defaultProps = {
  load: true,
};

export function Packages(props: PackageReportProps) {
  const {
    securityDetails,
    isSecurityDetailsLoading,
    isSecurityDetailsError,
    securityDetailsError,
  } = useManifestSecurity(
    props.org,
    props.repo,
    props.digest,
    props.load && props.digest !== '',
  );

  if (isSecurityDetailsError) {
    return (
      <RequestError
        title="Unable to package report"
        message={addDisplayError(
          securityDetailsError.toString(),
          securityDetailsError as Error,
        )}
      />
    );
  }

  // Return correct messages for the different scan states
  if (securityDetails?.status === 'queued') {
    return <QueuedState />;
  } else if (securityDetails?.status === 'failed') {
    return <FailedState />;
  } else if (
    securityDetails?.status === 'unsupported' ||
    securityDetails?.data?.Layer?.Features?.length == 0
  ) {
    return <UnsupportedState />;
  }

  // Set features to a default of null to distinuish between a completed API call and one that is in progress
  const features = securityDetails ? securityDetails.data.Layer.Features : null;
  return (
    <>
      <PackagesChart features={features} loading={isSecurityDetailsLoading} />
      <hr />
      <PackagesTable features={features} loading={isSecurityDetailsLoading} />
    </>
  );
}
