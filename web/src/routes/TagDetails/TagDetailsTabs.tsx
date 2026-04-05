import {Tabs, Tab, TabTitleText} from '@patternfly/react-core';
import {useSearchParams, useNavigate, useLocation} from 'react-router-dom';
import {useState, useEffect} from 'react';
import Details from './Details/Details';
import SecurityReport from './SecurityReport/SecurityReport';
import {ModelCard} from './ModelCard/ModelCard';
import HelmChartView from './HelmChart/HelmChartView';
import {Tag, ManifestByDigestResponse} from 'src/resources/TagResource';
import {TabIndex} from './Types';
import {Packages} from './Packages/Packages';
import {Layers} from './Layers/Layers';
import {useQuayConfig} from 'src/hooks/UseQuayConfig';

function getTabIndex(tab: string) {
  if (Object.values(TabIndex).includes(tab as TabIndex)) {
    return tab as TabIndex;
  }
}

export default function TagTabs(props: TagTabsProps) {
  const quayConfig = useQuayConfig();
  const isHelmChart = props.manifestData?.is_helm_chart === true;

  const [searchParams] = useSearchParams();
  const requestedTabIndex = getTabIndex(searchParams.get('tab'));
  const defaultTab = isHelmChart ? TabIndex.HelmChart : TabIndex.Details;
  const [activeTabKey, setActiveTabKey] = useState<TabIndex>(
    requestedTabIndex || defaultTab,
  );
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (
      isHelmChart &&
      !requestedTabIndex &&
      activeTabKey === TabIndex.Details
    ) {
      setActiveTabKey(TabIndex.HelmChart);
    }
  }, [isHelmChart]);

  if (requestedTabIndex && requestedTabIndex !== activeTabKey) {
    setActiveTabKey(requestedTabIndex);
  }

  return (
    <Tabs
      activeKey={activeTabKey}
      onSelect={(e, tabIndex) => {
        navigate(`${location.pathname}?tab=${tabIndex}`);
      }}
      usePageInsets={true}
    >
      <Tab
        eventKey={TabIndex.HelmChart}
        title={<TabTitleText>Helm Chart</TabTitleText>}
        isHidden={!isHelmChart}
      >
        <HelmChartView
          org={props.org}
          repo={props.repo}
          digest={props.digest}
          size={props.tag.size}
        />
      </Tab>
      <Tab
        eventKey={TabIndex.Details}
        title={<TabTitleText>Details</TabTitleText>}
      >
        <Details
          org={props.org}
          repo={props.repo}
          tag={props.tag}
          digest={props.digest}
        />
      </Tab>
      <Tab
        eventKey={TabIndex.Layers}
        title={<TabTitleText>Layers</TabTitleText>}
        isHidden={isHelmChart}
      >
        <Layers org={props.org} repo={props.repo} digest={props.digest} />
      </Tab>
      <Tab
        eventKey={TabIndex.SecurityReport}
        title={<TabTitleText>Security Report</TabTitleText>}
        isHidden={!quayConfig?.features?.SECURITY_SCANNER || isHelmChart}
      >
        <SecurityReport
          org={props.org}
          repo={props.repo}
          digest={props.digest}
        />
      </Tab>
      <Tab
        eventKey={TabIndex.Packages}
        title={<TabTitleText>Packages</TabTitleText>}
        isHidden={!quayConfig?.features?.SECURITY_SCANNER || isHelmChart}
      >
        <Packages
          org={props.org}
          repo={props.repo}
          digest={props.digest}
          layers={props.manifestData?.layers}
        />
      </Tab>
      <Tab
        eventKey={TabIndex.ModelCard}
        title={<TabTitleText>Model Card</TabTitleText>}
        isHidden={!quayConfig?.features?.UI_MODELCARD || !props.tag.modelcard}
      >
        <ModelCard modelCard={props.tag.modelcard} />
      </Tab>
    </Tabs>
  );
}

type TagTabsProps = {
  tag: Tag;
  org: string;
  repo: string;
  digest: string;
  manifestData: ManifestByDigestResponse | null;
  err: string;
};
