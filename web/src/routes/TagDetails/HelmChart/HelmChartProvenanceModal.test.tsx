import React from 'react';
import {render, screen} from '@testing-library/react';
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';

const mockUseHelmProvenance = jest.fn();

jest.mock('src/hooks/UseHelmChart', () => ({
  useHelmProvenance: (...args: unknown[]) => mockUseHelmProvenance(...args),
}));

import HelmChartProvenanceModal from './HelmChartProvenanceModal';

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

test('renders nothing visible when modal is closed', () => {
  mockUseHelmProvenance.mockReturnValue({
    data: undefined,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartProvenanceModal
      isOpen={false}
      onClose={jest.fn()}
      org="testorg"
      repo="testrepo"
      digest="sha256:abc"
    />,
  );

  expect(screen.queryByText('Provenance')).toBeNull();
});

test('shows spinner while loading', () => {
  mockUseHelmProvenance.mockReturnValue({
    data: undefined,
    isLoading: true,
    isError: false,
  });

  renderWithQuery(
    <HelmChartProvenanceModal
      isOpen={true}
      onClose={jest.fn()}
      org="testorg"
      repo="testrepo"
      digest="sha256:abc"
    />,
  );

  expect(screen.getByLabelText('Loading provenance')).toBeTruthy();
});

test('shows alert when provenance is not available', () => {
  mockUseHelmProvenance.mockReturnValue({
    data: undefined,
    isLoading: false,
    isError: true,
  });

  renderWithQuery(
    <HelmChartProvenanceModal
      isOpen={true}
      onClose={jest.fn()}
      org="testorg"
      repo="testrepo"
      digest="sha256:abc"
    />,
  );

  expect(screen.getByText('Provenance data not available')).toBeTruthy();
});

test('renders provenance content when available', () => {
  const provenanceText =
    '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\nname: test-chart\nversion: 1.0.0\n-----END PGP SIGNED MESSAGE-----';

  mockUseHelmProvenance.mockReturnValue({
    data: provenanceText,
    isLoading: false,
    isError: false,
  });

  renderWithQuery(
    <HelmChartProvenanceModal
      isOpen={true}
      onClose={jest.fn()}
      org="testorg"
      repo="testrepo"
      digest="sha256:abc"
    />,
  );

  expect(screen.getByTestId('helm-provenance-content')).toHaveTextContent(
    'BEGIN PGP SIGNED MESSAGE',
  );
});
