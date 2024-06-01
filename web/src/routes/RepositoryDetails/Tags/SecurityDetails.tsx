import {Link, useLocation} from 'react-router-dom';
import {Skeleton} from '@patternfly/react-core';
import {getTagDetailPath} from 'src/routes/NavigationPath';
import {TabIndex} from 'src/routes/TagDetails/Types';
import {
  ExclamationTriangleIcon,
  CheckCircleIcon,
} from '@patternfly/react-icons';
import {getSeverityColor} from 'src/libs/utils';
import {VulnerabilitySeverity} from 'src/resources/ManifestSecurityResource';
import {useManifestSecuritySummary} from 'src/hooks/UseManifestSecurity';

enum Variant {
  condensed = 'condensed',
  full = 'full',
}

export interface SecurityDetailsProps {
  org: string;
  repo: string;
  tag: string;
  digest: string;
  variant?: Variant | 'condensed' | 'full';
  load?: boolean;
}

SecurityDetails.defaultProps = {
  load: true,
};

export default function SecurityDetails(props: SecurityDetailsProps) {
  const location = useLocation();

  const severityOrder = [
    VulnerabilitySeverity.Critical,
    VulnerabilitySeverity.High,
    VulnerabilitySeverity.Medium,
    VulnerabilitySeverity.Low,
    VulnerabilitySeverity.Negligible,
    VulnerabilitySeverity.Unknown,
  ];

  const {securitySummary, isSecuritySummaryLoading, isSecuritySummaryError} =
    useManifestSecuritySummary(
      props.org,
      props.repo,
      props.digest,
      props.load && props.digest !== '',
    );

  const queryParams = new Map<string, string>([
    ['tab', TabIndex.SecurityReport],
    ['digest', props.digest],
  ]);

  if (isSecuritySummaryLoading) {
    return <Skeleton width="50%"></Skeleton>;
  }

  if (isSecuritySummaryError) {
    return <>Unable to get security details</>;
  }

  if (securitySummary === null || securitySummary === undefined) {
    return <>Security details not available</>;
  }

  if (securitySummary.status === 'queued') {
    return <div>Queued</div>;
  } else if (securitySummary.status === 'failed') {
    return <div>Failed</div>;
  } else if (securitySummary.status === 'unsupported') {
    return <div>Unsupported</div>;
  }

  const vulnSummary = securitySummary.data;

  if (vulnSummary.size === 0) {
    return (
      <Link
        to={getTagDetailPath(
          location.pathname,
          props.org,
          props.repo,
          props.tag,
          queryParams,
        )}
        className={'pf-v5-u-display-inline-flex pf-v5-u-align-items-center'}
        style={{textDecoration: 'none'}}
      >
        <CheckCircleIcon
          color="green"
          style={{
            marginRight: '5px',
            marginBottom: '4px',
          }}
        />
        <span>None Detected</span>
      </Link>
    );
  }

  if (props.variant === Variant.condensed) {
    let highestSeverity: VulnerabilitySeverity;

    for (const severity of severityOrder) {
      if (vulnSummary.get(severity) != null && vulnSummary.get(severity) > 0) {
        highestSeverity = severity;
        break;
      }
    }

    return (
      <Link
        to={getTagDetailPath(
          location.pathname,
          props.org,
          props.repo,
          props.tag,
          queryParams,
        )}
        className={'pf-v5-u-display-inline-flex pf-v5-u-align-items-center'}
        style={{textDecoration: 'none'}}
      >
        <ExclamationTriangleIcon
          color={getSeverityColor(highestSeverity)}
          style={{
            marginRight: '5px',
            marginBottom: '4px',
          }}
        />
        <span>
          <b>{vulnSummary.get(highestSeverity)}</b> {highestSeverity.toString()}
        </span>
      </Link>
    );
  }

  const counts = severityOrder
    .filter((severity) => vulnSummary.has(severity))
    .map((severity) => {
      return (
        <div
          key={severity.toString()}
          className={'pf-v5-u-display-flex pf-v5-u-align-items-center'}
        >
          <ExclamationTriangleIcon
            color={getSeverityColor(severity)}
            style={{
              marginRight: '5px',
              marginBottom: '3px',
            }}
          />
          <span>
            <b>{vulnSummary.get(severity)}</b> {severity.toString()}
          </span>
        </div>
      );
    });
  return (
    <Link
      to={getTagDetailPath(
        location.pathname,
        props.org,
        props.repo,
        props.tag,
        queryParams,
      )}
      style={{textDecoration: 'none'}}
    >
      {counts}
    </Link>
  );
}
