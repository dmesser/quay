import React from 'react';
import {render, screen} from '@testing-library/react';
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';

const mockUseHelmReadme = jest.fn();

jest.mock('src/hooks/UseHelmChart', () => ({
  useHelmReadme: (...args: unknown[]) => mockUseHelmReadme(...args),
}));

jest.mock('react-markdown', () => {
  return function MockMarkdown({children}: {children: string}) {
    return <div data-testid="helm-readme-markdown">{children}</div>;
  };
});

jest.mock('remark-gfm', () => () => null);
jest.mock('rehype-raw', () => () => null);
jest.mock('rehype-sanitize', () => () => null);

import HelmChartReadme from './HelmChartReadme';

function renderWithQuery(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {queries: {retry: false}},
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

test('renders markdown content', () => {
  mockUseHelmReadme.mockReturnValue({
    data: '# My Chart\n\nThis is the README.',
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartReadme org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByTestId('helm-readme-markdown')).toHaveTextContent(
    'My Chart',
  );
});

test('shows spinner while loading', () => {
  mockUseHelmReadme.mockReturnValue({
    data: undefined,
    isLoading: true,
    isError: false,
  });

  renderWithQuery(
    <HelmChartReadme org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByLabelText('Loading README')).toBeTruthy();
});

test('shows alert when readme is not available', () => {
  mockUseHelmReadme.mockReturnValue({
    data: undefined,
    isLoading: false,
    isError: true,
  });

  renderWithQuery(
    <HelmChartReadme org="testorg" repo="testrepo" digest="sha256:abc" />,
  );

  expect(screen.getByText('No README available')).toBeTruthy();
});
