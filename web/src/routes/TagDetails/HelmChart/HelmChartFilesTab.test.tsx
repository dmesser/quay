import React from 'react';
import {render, screen, fireEvent} from '@testing-library/react';
import HelmChartFilesTab from './HelmChartFilesTab';

test('shows message when file tree is empty', () => {
  render(<HelmChartFilesTab fileTree={[]} />);
  expect(screen.getByText('No files available.')).toBeTruthy();
});

test('renders file tree with flat files', () => {
  const fileTree = [
    {path: 'Chart.yaml', size: 300},
    {path: 'values.yaml', size: 1200},
  ];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  expect(screen.getByText(/Chart\.yaml/)).toBeTruthy();
  expect(screen.getByText(/values\.yaml/)).toBeTruthy();
});

test('renders nested directory structure', () => {
  const fileTree = [
    {path: 'Chart.yaml', size: 300},
    {path: 'templates/deployment.yaml', size: 3200},
    {path: 'templates/service.yaml', size: 1500},
  ];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  expect(screen.getByText('templates')).toBeTruthy();
  expect(screen.getByText(/deployment\.yaml/)).toBeTruthy();
  expect(screen.getByText(/service\.yaml/)).toBeTruthy();
});

test('displays file sizes', () => {
  const fileTree = [{path: 'values.yaml', size: 45000}];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  expect(screen.getByText(/45/)).toBeTruthy();
});

test('renders search input', () => {
  const fileTree = [{path: 'Chart.yaml', size: 300}];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  expect(screen.getByTestId('helm-filetree-search')).toBeTruthy();
});

test('filters files by search term', () => {
  const fileTree = [
    {path: 'Chart.yaml', size: 300},
    {path: 'values.yaml', size: 1200},
    {path: 'templates/deployment.yaml', size: 3200},
    {path: 'templates/service.yaml', size: 1500},
  ];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  const searchInput = screen.getByLabelText('Filter file tree');
  fireEvent.change(searchInput, {target: {value: 'deployment'}});

  expect(screen.getByText(/deployment\.yaml/)).toBeTruthy();
  expect(screen.queryByText(/Chart\.yaml/)).toBeNull();
  expect(screen.queryByText(/values\.yaml/)).toBeNull();
});

test('shows no matching message when filter has no results', () => {
  const fileTree = [
    {path: 'Chart.yaml', size: 300},
    {path: 'values.yaml', size: 1200},
  ];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  const searchInput = screen.getByLabelText('Filter file tree');
  fireEvent.change(searchInput, {target: {value: 'nonexistent'}});

  expect(screen.getByText('No files matching your search.')).toBeTruthy();
});

test('clearing search shows all files again', () => {
  const fileTree = [
    {path: 'Chart.yaml', size: 300},
    {path: 'values.yaml', size: 1200},
  ];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  const searchInput = screen.getByLabelText('Filter file tree');
  fireEvent.change(searchInput, {target: {value: 'chart'}});

  expect(screen.getByText(/Chart\.yaml/)).toBeTruthy();
  expect(screen.queryByText(/values\.yaml/)).toBeNull();

  fireEvent.change(searchInput, {target: {value: ''}});

  expect(screen.getByText(/Chart\.yaml/)).toBeTruthy();
  expect(screen.getByText(/values\.yaml/)).toBeTruthy();
});

test('handles deeply nested directory structures', () => {
  const fileTree = [
    {path: 'charts/subchart/templates/configmap.yaml', size: 500},
  ];

  render(<HelmChartFilesTab fileTree={fileTree} />);

  expect(screen.getByText('charts')).toBeTruthy();
  expect(screen.getByText('subchart')).toBeTruthy();
  expect(screen.getByText('templates')).toBeTruthy();
  expect(screen.getByText(/configmap\.yaml/)).toBeTruthy();
});
