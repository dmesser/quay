import RequestError from 'src/components/errors/RequestError';
import {useManifestSecurity} from 'src/hooks/UseManifestSecurity';
import {addDisplayError} from 'src/resources/ErrorHandling';
import {SecurityReportChart} from './SecurityReportChart';
import {
  FailedState,
  NoVulnerabilitiesState,
  QueuedState,
  UnsupportedState,
} from './SecurityReportScanStates';
import SecurityReportTable from './SecurityReportTable';

export interface SecurityReportProps {
  org: string;
  repo: string;
  digest: string;
  load?: boolean;
}

SecurityReport.defaultProps = {
  load: true,
};

export default function SecurityReport(props: SecurityReportProps) {
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
        title="Unable to load security details"
        message={addDisplayError(
          securityDetailsError.toString(),
          securityDetailsError as Error,
        )}
      />
    );
  }

  if (securityDetails?.status === 'queued') {
    // Return correct messages for the different scan states
    return <QueuedState />;
  } else if (securityDetails?.status === 'failed') {
    return <FailedState />;
  } else if (
    securityDetails?.status === 'unsupported' ||
    securityDetails?.data?.Layer?.Features?.length == 0
  ) {
    return <UnsupportedState />;
  } else if (
    !isSecurityDetailsLoading &&
    !securityDetails?.data?.Layer?.Features?.some(
      (feature) =>
        feature.Vulnerabilities && feature.Vulnerabilities.length > 0,
    )
  ) {
    return <NoVulnerabilitiesState />;
  }

  // Set features to a default of null to distinuish between a completed API call and one that is in progress
  const features = securityDetails ? securityDetails.data.Layer.Features : null;

  return (
    <>
      <SecurityReportChart
        features={features}
        loading={isSecurityDetailsLoading}
      />
      <hr />
      <SecurityReportTable
        features={features}
        loading={isSecurityDetailsLoading}
      />
    </>
  );
}
