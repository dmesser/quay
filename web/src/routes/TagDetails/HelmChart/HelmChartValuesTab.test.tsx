import React from 'react';
import {render, screen, fireEvent} from '@testing-library/react';
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';

const mockUseHelmValues = jest.fn();

jest.mock('src/hooks/UseHelmChart', () => ({
  useHelmValues: (...args: unknown[]) => mockUseHelmValues(...args),
}));

jest.mock('src/contexts/ThemeContext', () => ({
  useTheme: () => ({isDarkTheme: false}),
}));

jest.mock('@patternfly/react-code-editor', () => {
  const React = require('react');
  return {
    CodeEditor: (props: Record<string, unknown>) =>
      React.createElement(
        'pre',
        {'data-testid': 'mock-code-editor'},
        props.code,
      ),
    Language: {yaml: 'yaml'},
  };
});

import HelmChartValuesTab from './HelmChartValuesTab';

function renderWithQuery(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {queries: {retry: false}},
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

beforeEach(() => {
  jest.clearAllMocks();
});

test('shows spinner while loading', () => {
  mockUseHelmValues.mockReturnValue({
    data: undefined,
    isLoading: true,
    isError: false,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByLabelText('Loading values.yaml')).toBeTruthy();
});

test('shows alert when values are not available', () => {
  mockUseHelmValues.mockReturnValue({
    data: undefined,
    isLoading: false,
    isError: true,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('values.yaml not available')).toBeTruthy();
});

test('shows alert when values data is null', () => {
  mockUseHelmValues.mockReturnValue({
    data: null,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('values.yaml not available')).toBeTruthy();
});

const sampleYaml = [
  'replicaCount: 1',
  'image:',
  '  registry: docker.io',
  '  repository: bitnami/nginx',
  '  tag: 1.27.5',
  'service:',
  '  type: ClusterIP',
  '  port: 80',
].join('\n');

test('renders code editor with YAML content', () => {
  mockUseHelmValues.mockReturnValue({
    data: sampleYaml,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByTestId('helm-values-content')).toBeTruthy();
  expect(screen.getByTestId('mock-code-editor')).toHaveTextContent(
    'replicaCount: 1',
  );
});

test('renders the search input for YAML path navigation', () => {
  mockUseHelmValues.mockReturnValue({
    data: sampleYaml,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByTestId('helm-values-search')).toBeTruthy();
});

test('shows filtered suggestions when typing in the search input', () => {
  mockUseHelmValues.mockReturnValue({
    data: sampleYaml,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  const searchInput = screen.getByLabelText('Search YAML paths');
  fireEvent.change(searchInput, {target: {value: 'image'}});
  fireEvent.focus(searchInput);

  expect(screen.getByText('image.registry')).toBeTruthy();
  expect(screen.getByText('image.repository')).toBeTruthy();
  expect(screen.getByText('image.tag')).toBeTruthy();
});

test('shows "No matching paths" when search has no results', () => {
  mockUseHelmValues.mockReturnValue({
    data: sampleYaml,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  const searchInput = screen.getByLabelText('Search YAML paths');
  fireEvent.change(searchInput, {target: {value: 'nonexistent'}});

  expect(screen.getByText('No matching paths')).toBeTruthy();
});

test('hides suggestions when search input is cleared', () => {
  mockUseHelmValues.mockReturnValue({
    data: sampleYaml,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartValuesTab org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  const searchInput = screen.getByLabelText('Search YAML paths');
  fireEvent.change(searchInput, {target: {value: 'image'}});

  expect(screen.getByText('image.registry')).toBeTruthy();

  fireEvent.change(searchInput, {target: {value: ''}});
  expect(screen.queryByText('image.registry')).toBeNull();
});
