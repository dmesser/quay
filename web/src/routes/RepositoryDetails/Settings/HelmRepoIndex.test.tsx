import React from 'react';
import {render, screen, fireEvent} from '@testing-library/react';

const mockUpdateConfig = jest.fn();
let mockConfigReturn: Record<string, unknown> = {
  config: undefined,
  isLoading: true,
  error: null,
};
let mockUpdateReturn: Record<string, unknown> = {
  updateConfig: mockUpdateConfig,
  isUpdating: false,
};
let capturedCallbacks = {} as {
  onSuccess?: () => void;
  onError?: (error: unknown) => void;
};

jest.mock('src/hooks/UseHelmRepoIndex', () => ({
  useHelmRepoIndexConfig: () => mockConfigReturn,
  useUpdateHelmRepoIndexConfig: (_org, _repo, opts) => {
    capturedCallbacks = opts;
    return mockUpdateReturn;
  },
}));

jest.mock('src/hooks/UseQuayConfig', () => ({
  useQuayConfig: () => ({
    config: {SERVER_HOSTNAME: 'quay.example.com'},
    features: {HELM_REPO_INDEX: true},
  }),
}));

jest.mock('src/contexts/UIContext', () => ({
  ...jest.requireActual('src/contexts/UIContext'),
  useUI: () => ({
    addAlert: jest.fn(),
    alerts: [],
    removeAlert: jest.fn(),
    clearAllAlerts: jest.fn(),
    isSidebarOpen: false,
    toggleSidebar: jest.fn(),
  }),
}));

jest.mock('src/components/errors/RequestError', () => {
  const React = require('react');
  return function MockRequestError() {
    return React.createElement(
      'div',
      {'data-testid': 'request-error'},
      'Request Error',
    );
  };
});

import HelmRepoIndex from './HelmRepoIndex';

beforeEach(() => {
  jest.clearAllMocks();
  mockConfigReturn = {
    config: undefined,
    isLoading: true,
    error: null,
  };
  mockUpdateReturn = {
    updateConfig: mockUpdateConfig,
    isUpdating: false,
  };
  capturedCallbacks = {};
});

test('shows spinner while loading config', () => {
  mockConfigReturn = {config: undefined, isLoading: true, error: null};
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);
  expect(screen.getByRole('progressbar')).toBeTruthy();
});

test('shows error component on fetch failure', () => {
  mockConfigReturn = {
    config: undefined,
    isLoading: false,
    error: new Error('fetch failed'),
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);
  expect(screen.getByTestId('request-error')).toBeTruthy();
});

test('renders disabled state by default', () => {
  mockConfigReturn = {
    config: {enabled: false, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  expect(screen.getByText('Helm Repository Index')).toBeTruthy();
  expect(screen.getByTestId('helm-index-info-alert')).toBeTruthy();

  const toggle = screen.getByTestId('helm-repo-index-toggle');
  expect(toggle).toBeTruthy();
  expect(toggle).not.toBeChecked();

  expect(screen.queryByTestId('helm-repo-index-tag-pattern')).toBeNull();
  expect(screen.queryByTestId('helm-repo-add-command')).toBeNull();
});

test('shows tag pattern and usage when enabled', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  expect(screen.getByTestId('helm-repo-index-tag-pattern')).toBeTruthy();
  expect(screen.getByTestId('helm-repo-add-command')).toBeTruthy();
});

test('displays correct helm repo add command', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="myorg" repo="myrepo" />);

  expect(
    screen.getByDisplayValue(
      /helm repo add myrepo.*quay\.example\.com\/myorg\/myrepo/,
    ),
  ).toBeTruthy();
});

test('save button is disabled when no changes are made', () => {
  mockConfigReturn = {
    config: {enabled: false, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  expect(saveBtn).toBeDisabled();
});

test('save button is enabled after toggling', () => {
  mockConfigReturn = {
    config: {enabled: false, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const toggle = screen.getByTestId('helm-repo-index-toggle');
  fireEvent.click(toggle);

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  expect(saveBtn).not.toBeDisabled();
});

test('allows save with any pattern and relies on server-side validation', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const patternInput = screen.getByTestId('helm-repo-index-tag-pattern');
  fireEvent.change(patternInput, {target: {value: '[invalid'}});

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  expect(saveBtn).not.toBeDisabled();
});

test('displays server-side pattern validation error inline', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const patternInput = screen.getByTestId('helm-repo-index-tag-pattern');
  fireEvent.change(patternInput, {target: {value: '[invalid'}});

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  fireEvent.click(saveBtn);

  expect(capturedCallbacks.onError).toBeDefined();
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  capturedCallbacks.onError!(new Error('Invalid regex pattern: missing ]'));

  expect(screen.getByText('Invalid regex pattern: missing ]')).toBeTruthy();
  expect(saveBtn).toBeDisabled();
});

test('clears pattern error on successful save', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const patternInput = screen.getByTestId('helm-repo-index-tag-pattern');
  fireEvent.change(patternInput, {target: {value: '^v[0-9]+'}});

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  fireEvent.click(saveBtn);

  expect(capturedCallbacks.onSuccess).toBeDefined();
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  capturedCallbacks.onSuccess!();

  expect(
    screen.getByText(
      'Optional regex to filter which tags are included. Leave empty to include all Helm chart tags.',
    ),
  ).toBeTruthy();
});

test('validates pattern length limit', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const patternInput = screen.getByTestId('helm-repo-index-tag-pattern');
  fireEvent.change(patternInput, {target: {value: 'x'.repeat(300)}});

  expect(
    screen.getByText('Tag pattern must be 256 characters or less'),
  ).toBeTruthy();
});

test('calls updateConfig on save with null tagPattern when pattern is empty', () => {
  mockConfigReturn = {
    config: {enabled: false, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const toggle = screen.getByTestId('helm-repo-index-toggle');
  fireEvent.click(toggle);

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  fireEvent.click(saveBtn);

  expect(mockUpdateConfig).toHaveBeenCalledWith({
    enabled: true,
    tagPattern: null,
  });
});

test('calls updateConfig with tag pattern string when provided', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: null},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const patternInput = screen.getByTestId('helm-repo-index-tag-pattern');
  fireEvent.change(patternInput, {target: {value: '^v[0-9]+'}});

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  fireEvent.click(saveBtn);

  expect(mockUpdateConfig).toHaveBeenCalledWith({
    enabled: true,
    tagPattern: '^v[0-9]+',
  });
});

test('calls updateConfig when disabling preserves existing tagPattern', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: '^v.*'},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const toggle = screen.getByTestId('helm-repo-index-toggle');
  fireEvent.click(toggle);

  const saveBtn = screen.getByTestId('helm-repo-index-save-btn');
  fireEvent.click(saveBtn);

  expect(mockUpdateConfig).toHaveBeenCalledWith({
    enabled: false,
    tagPattern: '^v.*',
  });
});

test('populates form from existing config', () => {
  mockConfigReturn = {
    config: {enabled: true, tagPattern: '^v[0-9]+.*'},
    isLoading: false,
    error: null,
  };
  render(<HelmRepoIndex org="testorg" repo="testrepo" />);

  const toggle = screen.getByTestId('helm-repo-index-toggle');
  expect(toggle).toBeChecked();

  const patternInput = screen.getByTestId('helm-repo-index-tag-pattern');
  expect(patternInput).toHaveValue('^v[0-9]+.*');
});
