import React from 'react';
import {render, screen} from '@testing-library/react';
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';

const mockUseHelmChartMetadata = jest.fn();

jest.mock('src/hooks/UseHelmChart', () => ({
  useHelmChartMetadata: (...args: unknown[]) =>
    mockUseHelmChartMetadata(...args),
  useHelmIcon: () => ({data: null, isLoading: false, isError: false}),
  useHelmReadme: () => ({data: null, isLoading: false, isError: false}),
  useHelmValues: () => ({data: null, isLoading: false, isError: false}),
  useHelmProvenance: () => ({data: null, isLoading: false, isError: false}),
}));

jest.mock('src/hooks/UseQuayConfig', () => ({
  useQuayConfig: () => ({
    config: {SERVER_HOSTNAME: 'quay.example.com'},
    features: {},
  }),
}));

jest.mock('react-markdown', () => {
  return function MockMarkdown({children}: {children: string}) {
    return <div>{children}</div>;
  };
});
jest.mock('remark-gfm', () => () => null);
jest.mock('rehype-raw', () => () => null);
jest.mock('rehype-sanitize', () => () => null);

import HelmChartView from './HelmChartView';

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {queries: {retry: false}},
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

test('shows loading spinner while metadata is loading', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: undefined,
    isLoading: true,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByLabelText('Loading Helm chart metadata')).toBeTruthy();
});

test('shows error alert on fetch failure', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: undefined,
    isLoading: false,
    isError: true,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('Failed to load Helm chart metadata')).toBeTruthy();
});

test('shows pending alert when extraction is in progress', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {extraction_status: 'pending'},
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByTestId('helm-pending-alert')).toBeTruthy();
});

test('shows failed alert when extraction has failed', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'failed',
      extraction_error: 'Chart.yaml missing',
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByTestId('helm-failed-alert')).toBeTruthy();
  expect(screen.getByText('Chart.yaml missing')).toBeTruthy();
});

test('renders header and sidebar for completed extraction', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'completed',
      chart_name: 'test-chart',
      chart_version: '1.0.0',
      api_version: 'v2',
      description: 'A test chart',
      has_readme: true,
      has_values: false,
      has_schema: false,
      has_provenance: false,
      has_icon: false,
      file_tree: [],
      keywords: ['test'],
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByTestId('helm-sidebar')).toBeTruthy();
  expect(screen.getByTestId('helm-chart-title')).toHaveTextContent(
    'test-chart',
  );
  expect(screen.getByText('A test chart')).toBeTruthy();
});

test('shows pull and install commands inline in header', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'completed',
      chart_name: 'my-chart',
      chart_version: '2.0.0',
      api_version: 'v2',
      has_readme: false,
      has_values: false,
      has_schema: false,
      has_provenance: false,
      has_icon: false,
      file_tree: [],
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByTestId('helm-pull-command')).toBeTruthy();
  expect(screen.getByTestId('helm-install-command')).toBeTruthy();
});

test('shows Values tab when has_values is true', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'completed',
      chart_name: 'test-chart',
      chart_version: '1.0.0',
      api_version: 'v2',
      has_readme: false,
      has_values: true,
      has_schema: false,
      has_provenance: false,
      has_icon: false,
      file_tree: [],
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('Values')).toBeTruthy();
});

test('shows separate Files and Dependencies tabs', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'completed',
      chart_name: 'test-chart',
      chart_version: '1.0.0',
      api_version: 'v2',
      has_readme: false,
      has_values: false,
      has_schema: false,
      has_provenance: false,
      has_icon: false,
      file_tree: [
        {path: 'Chart.yaml', size: 300},
        {path: 'values.yaml', size: 1200},
      ],
      dependencies: [{name: 'common', version: '2.x.x'}],
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('Files')).toBeTruthy();
  expect(screen.getByText('Dependencies')).toBeTruthy();
});

test('renders keywords as labels in sidebar', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'completed',
      chart_name: 'test-chart',
      chart_version: '1.0.0',
      api_version: 'v2',
      has_readme: false,
      has_values: false,
      has_schema: false,
      has_provenance: false,
      has_icon: false,
      file_tree: [],
      keywords: ['database', 'sql'],
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('database')).toBeTruthy();
  expect(screen.getByText('sql')).toBeTruthy();
});

test('shows deprecated label when chart is deprecated', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'completed',
      chart_name: 'old-chart',
      chart_version: '0.1.0',
      api_version: 'v2',
      deprecated: true,
      has_readme: false,
      has_values: false,
      has_schema: false,
      has_provenance: false,
      has_icon: false,
      file_tree: [],
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('Deprecated')).toBeTruthy();
});

test('Readme tab is selected by default', () => {
  mockUseHelmChartMetadata.mockReturnValue({
    data: {
      extraction_status: 'completed',
      chart_name: 'test-chart',
      chart_version: '1.0.0',
      api_version: 'v2',
      has_readme: true,
      has_values: true,
      has_schema: false,
      has_provenance: false,
      has_icon: false,
      file_tree: [{path: 'Chart.yaml', size: 300}],
      dependencies: [{name: 'common', version: '2.x.x'}],
    },
    isLoading: false,
    isError: false,
  });

  renderWithProviders(
    <HelmChartView org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  const readmeTab = screen.getByRole('tab', {name: /readme/i});
  expect(readmeTab).toHaveAttribute('aria-selected', 'true');
});
