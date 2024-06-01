import {ChartDonut} from '@patternfly/react-charts';
import {
  PageSection,
  PageSectionVariants,
  Skeleton,
  Split,
  SplitItem,
  Title,
  TitleSizes,
} from '@patternfly/react-core';
import {getSeverityColor} from 'src/libs/utils';
import {
  Feature,
  VulnerabilitySeverity,
} from 'src/resources/ManifestSecurityResource';
import './SecurityReportChart.css';

function VulnerabilitySummary(props: VulnerabilityStatsProps) {
  let message = <></>;
  if (props.loading) {
    message = <Skeleton width="400px" />;
  } else if (props.total == 0) {
    message = <> Quay Security Reporting has detected no vulnerabilities </>;
  } else {
    message = (
      <> Quay Security Reporting has detected {props.total} vulnerabilities </>
    );
  }

  let patchesMessage = <></>;
  if (props.loading) {
    patchesMessage = <Skeleton width="300px" />;
  } else if (props.total == 0) {
    patchesMessage = <> </>;
  } else if (props.patchesAvailable > 0) {
    patchesMessage = (
      <> Patches are available for {props.patchesAvailable} vulnerabilities</>
    );
  } else if (props.patchesAvailable == 0) {
    patchesMessage = (
      <> No patches are available for the detected vulnerabilities</>
    );
  }

  return (
    <div>
      <div className="pf-v5-u-mt-xl pf-v5-u-ml-2xl">
        <Title
          headingLevel="h1"
          size={TitleSizes['3xl']}
          className="pf-v5-u-mb-sm"
        >
          {message}
        </Title>
        <Title headingLevel="h3" className="pf-v5-u-mb-lg">
          {patchesMessage}
        </Title>
      </div>
    </div>
  );
}

function VulnerabilityChart(props: VulnerabilityStatsProps) {
  return (
    <div style={{height: '20em', width: '20em'}}>
      {props.loading ? (
        <Skeleton shape="circle" width="100%" />
      ) : (
        <ChartDonut
          ariaDesc="vulnerability chart"
          ariaTitle="vulnerability chart"
          constrainToVisibleArea={true}
          data={[
            {x: VulnerabilitySeverity.Critical, y: props.stats.Critical},
            {x: VulnerabilitySeverity.High, y: props.stats.High},
            {x: VulnerabilitySeverity.Medium, y: props.stats.Medium},
            {x: VulnerabilitySeverity.Low, y: props.stats.Low},
            {x: VulnerabilitySeverity.Negligible, y: props.stats.Negligible},
            {x: VulnerabilitySeverity.Unknown, y: props.stats.Unknown},
          ]}
          colorScale={[
            getSeverityColor(VulnerabilitySeverity.Critical),
            getSeverityColor(VulnerabilitySeverity.High),
            getSeverityColor(VulnerabilitySeverity.Medium),
            getSeverityColor(VulnerabilitySeverity.Low),
            getSeverityColor(VulnerabilitySeverity.Negligible),
            getSeverityColor(VulnerabilitySeverity.Unknown),
          ]}
          labels={({datum}) => `${datum.x}: ${datum.y}`}
          title={`${props.total}`}
        />
      )}
    </div>
  );
}

export function SecurityReportChart(props: SecurityDetailsChartProps) {
  const stats: VulnerabilityStats = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Negligible: 0,
    Unknown: 0,
  };

  let patchesAvailable = 0;
  let total = 0;

  // Count vulnerabilities if API call has completed
  if (!props.loading && props.features) {
    props.features.map((feature) => {
      feature.Vulnerabilities.map((vulnerability) => {
        stats[vulnerability.Severity] += 1;
        total += 1;
        if (vulnerability.FixedBy.length > 0) {
          patchesAvailable += 1;
        }
      });
    });
  }

  return (
    <PageSection variant={PageSectionVariants.light}>
      <Split>
        <SplitItem data-testid="vulnerability-chart">
          <VulnerabilityChart
            stats={stats}
            total={total}
            patchesAvailable={patchesAvailable}
            loading={props.loading}
          />
        </SplitItem>
        <SplitItem>
          <VulnerabilitySummary
            stats={stats}
            total={total}
            patchesAvailable={patchesAvailable}
            loading={props.loading}
          />
        </SplitItem>
      </Split>
    </PageSection>
  );
}

export interface VulnerabilityStats {
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  Negligible: number;
  Unknown: number;
}

interface VulnerabilityStatsProps {
  stats: VulnerabilityStats;
  total: number;
  patchesAvailable: number;
  loading: boolean;
}

interface SecurityDetailsChartProps {
  features: Feature[];
  loading: boolean;
}
