import {test, expect} from '../../fixtures';
import {API_URL} from '../../utils/config';

const helmDigest =
  'sha256:aabbccddee00112233445566778899aabbccddee00112233445566778899aabb';

const helmMetadata = {
  extraction_status: 'completed',
  chart_name: 'nginx',
  chart_version: '22.6.10',
  app_version: '1.27.5',
  api_version: 'v2',
  description:
    'NGINX Open Source is a web server that can be also used as a reverse proxy, load balancer, and HTTP cache.',
  kube_version: '>=1.23.0-0',
  chart_type: 'application',
  home: 'https://github.com/bitnami/charts/tree/main/bitnami/nginx',
  deprecated: false,
  sources: ['https://github.com/bitnami/containers/tree/main/bitnami/nginx'],
  maintainers: [{name: 'Broadcom', url: 'https://github.com/bitnami/charts'}],
  dependencies: [
    {
      name: 'common',
      version: '2.x.x',
      repository: 'oci://registry-1.docker.io/bitnamicharts',
    },
  ],
  keywords: ['nginx', 'http', 'web', 'www', 'reverse proxy'],
  annotations: {},
  has_readme: true,
  has_values: true,
  has_schema: false,
  has_provenance: false,
  has_icon: false,
  icon_media_type: null,
  file_tree: [
    {path: 'Chart.yaml', size: 1200},
    {path: 'values.yaml', size: 45000},
    {path: 'README.md', size: 85000},
    {path: 'templates/deployment.yaml', size: 3200},
    {path: 'templates/service.yaml', size: 1500},
  ],
  image_references: [
    {
      image: 'docker.io/bitnami/nginx:1.27.5-debian-12-r1',
      location: 'values.yaml',
    },
  ],
};

const readmeContent = {
  content:
    '# NGINX\n\nNGINX Open Source is a web server.\n\n## TL;DR\n\n```bash\nhelm install my-release oci://registry/nginx\n```\n',
};

const valuesContent = {
  content:
    'replicaCount: 1\nimage:\n  registry: docker.io\n  repository: bitnami/nginx\n  tag: 1.27.5\nserver:\n  ingress:\n    enabled: false\n',
};

function setupHelmRoutes(
  page: import('@playwright/test').Page,
  metadataOverride?: Record<string, unknown>,
  tagName = '22.6.10',
) {
  const metadata = metadataOverride ?? helmMetadata;
  return Promise.all([
    page.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm`,
      (route) => route.fulfill({status: 200, json: metadata}),
    ),
    page.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/readme`,
      (route) => route.fulfill({status: 200, json: readmeContent}),
    ),
    page.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/values`,
      (route) => route.fulfill({status: 200, json: valuesContent}),
    ),
    page.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/icon`,
      (route) => route.fulfill({status: 404, json: {error: 'not found'}}),
    ),
    page.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/provenance`,
      (route) => route.fulfill({status: 404, json: {error: 'not found'}}),
    ),
    page.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/labels`,
      (route) => route.fulfill({status: 200, json: {labels: []}}),
    ),
    page.route(
      (url) => url.pathname.endsWith(`/manifest/${helmDigest}`),
      (route) =>
        route.fulfill({
          status: 200,
          json: {
            digest: helmDigest,
            is_manifest_list: false,
            manifest_data: '{}',
            config_media_type: 'application/vnd.cncf.helm.config.v1+json',
            is_helm_chart: true,
          },
        }),
    ),
    page.route('**/api/v1/repository/*/*/tag/*', (route) =>
      route.fulfill({
        status: 200,
        json: {
          tags: [
            {
              name: tagName,
              is_manifest_list: false,
              last_modified: 'Mon, 01 Jan 2026 00:00:00 -0000',
              manifest_digest: helmDigest,
              reversion: false,
              size: 50000,
              start_ts: 1735689600,
              is_helm_chart: true,
            },
          ],
          page: 1,
          has_additional: false,
        },
      }),
    ),
  ]);
}

// ============================================================================
// Tag Details: Helm Chart Tab
// ============================================================================

test.describe('Helm Chart Tag Details', {tag: ['@tags', '@helm']}, () => {
  test('Helm Chart tab is first and Layers tab is hidden', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto('/repository/user1/helm-charts/tag/22.6.10');

    await expect(authenticatedPage.getByText('Helm Chart')).toBeVisible();
    await expect(authenticatedPage.getByText('Layers')).not.toBeVisible();

    const tabs = authenticatedPage.locator('[role="tab"]:visible');
    const firstTab = tabs.first();
    await expect(firstTab).toContainText('Helm Chart');
  });

  test('Security Report and Packages tabs are hidden for Helm charts', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto('/repository/user1/helm-charts/tag/22.6.10');

    await expect(authenticatedPage.getByText('Helm Chart')).toBeVisible();
    await expect(
      authenticatedPage.getByRole('tab', {name: 'Security Report'}),
    ).not.toBeVisible();
    await expect(
      authenticatedPage.getByRole('tab', {name: 'Packages'}),
    ).not.toBeVisible();
  });

  test('renders README in main content and sidebar with chart info', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await expect(
      authenticatedPage.getByTestId('helm-readme-content'),
    ).toBeVisible();
    await expect(authenticatedPage.getByTestId('helm-sidebar')).toBeVisible();
    await expect(
      authenticatedPage.getByTestId('helm-chart-title'),
    ).toContainText('nginx');
  });

  test('Pull and install commands are shown inline in header', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const pullInput = authenticatedPage
      .getByTestId('helm-pull-command')
      .locator('input');
    await expect(pullInput).toHaveValue(
      /helm pull oci:\/\/.*\/user1\/helm-charts --version 22\.6\.10/,
    );

    const installInput = authenticatedPage
      .getByTestId('helm-install-command')
      .locator('input');
    await expect(installInput).toHaveValue(
      /helm install nginx oci:\/\/.*\/user1\/helm-charts --version 22\.6\.10/,
    );
  });

  test('Values tab shows inline code editor', async ({authenticatedPage}) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await authenticatedPage.getByRole('tab', {name: 'Values'}).click();
    await expect(
      authenticatedPage.getByTestId('helm-values-content'),
    ).toBeVisible();
  });

  test('Files tab shows file tree', async ({authenticatedPage}) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await authenticatedPage.getByRole('tab', {name: 'Files'}).click();
    await expect(
      authenticatedPage.getByTestId('helm-file-tree').first(),
    ).toBeVisible();
  });

  test('Dependencies tab shows deps table', async ({authenticatedPage}) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await authenticatedPage.getByRole('tab', {name: 'Dependencies'}).click();
    await expect(
      authenticatedPage.getByTestId('helm-deps-table'),
    ).toBeVisible();
    await expect(authenticatedPage.getByText('common')).toBeVisible();
  });
});

// ============================================================================
// Sidebar Details
// ============================================================================

test.describe('Helm Chart Sidebar Details', {tag: ['@tags', '@helm']}, () => {
  test('shows keyword tags in sidebar', async ({authenticatedPage}) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();
    await expect(sidebar.getByText('nginx', {exact: true})).toBeVisible();
    await expect(sidebar.getByText('http', {exact: true})).toBeVisible();
    await expect(sidebar.getByText('reverse proxy')).toBeVisible();
  });

  test('shows container image references in sidebar', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();
    await expect(sidebar.getByText('Container images')).toBeVisible();
    await expect(
      sidebar.getByText('docker.io/bitnami/nginx:1.27.5-debian-12-r1'),
    ).toBeVisible();
  });

  test('shows maintainer info in sidebar', async ({authenticatedPage}) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();
    await expect(sidebar.getByText('Maintainers')).toBeVisible();
    await expect(sidebar.getByText('Broadcom')).toBeVisible();
  });

  test('About card shows chart API, version, app version, type, and Kubernetes version', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();

    await expect(sidebar.getByText('About')).toBeVisible();
    await expect(sidebar.getByText('Chart API')).toBeVisible();

    const aboutCard = sidebar
      .locator('.pf-v6-c-card')
      .filter({hasText: 'About'})
      .first();
    await expect(aboutCard.getByText('v2')).toBeVisible();
    await expect(aboutCard.getByText('Chart version')).toBeVisible();
    await expect(aboutCard.getByText('22.6.10')).toBeVisible();
    await expect(aboutCard.getByText('App version')).toBeVisible();
    await expect(aboutCard.getByText('1.27.5', {exact: true})).toBeVisible();
    await expect(aboutCard.getByText('Type')).toBeVisible();
    await expect(aboutCard.getByText('application')).toBeVisible();
    await expect(aboutCard.getByText('Kubernetes')).toBeVisible();
    await expect(aboutCard.getByText('>=1.23.0-0')).toBeVisible();
  });

  test('Links card shows Homepage and Source links', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();

    await expect(sidebar.getByText('Links')).toBeVisible();

    const homepageLink = sidebar.getByRole('link', {name: 'Homepage'});
    await expect(homepageLink).toBeVisible();
    await expect(homepageLink).toHaveAttribute(
      'href',
      'https://github.com/bitnami/charts/tree/main/bitnami/nginx',
    );
    await expect(homepageLink).toHaveAttribute('target', '_blank');

    const sourceLink = sidebar.getByRole('link', {name: 'Source'});
    await expect(sourceLink).toBeVisible();
    await expect(sourceLink).toHaveAttribute(
      'href',
      'https://github.com/bitnami/containers/tree/main/bitnami/nginx',
    );
    await expect(sourceLink).toHaveAttribute('target', '_blank');
  });

  test('container image refs from quay.io are rendered as external links', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage, {
      ...helmMetadata,
      image_references: [
        {
          image: 'quay.io/bitnami/nginx:1.27.5',
          location: 'values.yaml',
        },
      ],
    });

    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();
    const imageLink = sidebar.getByRole('link', {
      name: /quay\.io\/bitnami\/nginx:1\.27\.5/,
    });
    await expect(imageLink).toBeVisible();
    await expect(imageLink).toHaveAttribute(
      'href',
      'https://quay.io/repository/bitnami/nginx/tag/1.27.5',
    );
    await expect(imageLink).toHaveAttribute('target', '_blank');
  });
});

// ============================================================================
// Chart Icon
// ============================================================================

test.describe('Helm Chart Icon', {tag: ['@tags', '@helm']}, () => {
  test('renders chart icon when icon data is available', async ({
    authenticatedPage,
  }) => {
    const pngBase64 =
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

    await setupHelmRoutes(authenticatedPage, {
      ...helmMetadata,
      has_icon: true,
    });

    await authenticatedPage.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/icon`,
      (route) =>
        route.fulfill({
          status: 200,
          json: {icon_data: pngBase64, media_type: 'image/png'},
        }),
    );

    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const icon = authenticatedPage.getByTestId('helm-chart-icon');
    await expect(icon).toBeVisible();
    await expect(icon).toHaveAttribute(
      'src',
      `data:image/png;base64,${pngBase64}`,
    );
  });

  test('renders letter avatar fallback when no icon', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await expect(
      authenticatedPage.getByTestId('helm-chart-icon'),
    ).not.toBeVisible();

    const header = authenticatedPage.getByTestId('helm-sidebar');
    await expect(header.getByText('N', {exact: true})).toBeVisible();
  });
});

// ============================================================================
// Deprecated Chart
// ============================================================================

test.describe('Helm Chart Deprecated', {tag: ['@tags', '@helm']}, () => {
  test('shows deprecated label for deprecated chart', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage, {
      ...helmMetadata,
      deprecated: true,
    });

    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await expect(authenticatedPage.getByText('Deprecated')).toBeVisible();
  });
});

// ============================================================================
// Provenance
// ============================================================================

test.describe('Helm Chart Provenance', {tag: ['@tags', '@helm']}, () => {
  test('shows provenance badge and opens modal', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage, {
      ...helmMetadata,
      has_provenance: true,
      provenance_key_id: 'ABCD1234',
      provenance_hash_algorithm: 'SHA512',
      provenance_signature_date: '2026-01-01T00:00:00Z',
    });
    await authenticatedPage.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/provenance`,
      (route) =>
        route.fulfill({
          status: 200,
          json: {content: '-----BEGIN PGP SIGNED MESSAGE-----\ntest'},
        }),
    );

    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await expect(
      authenticatedPage.getByTestId('helm-provenance-badge').first(),
    ).toBeVisible();

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();
    await expect(sidebar.getByText('Key ID')).toBeVisible();
    await expect(sidebar.getByText('ABCD1234')).toBeVisible();

    await sidebar.getByTestId('helm-provenance-link').click();
    await expect(
      authenticatedPage.getByTestId('helm-provenance-modal'),
    ).toBeVisible();
  });

  test('provenance modal displays PGP signed content', async ({
    authenticatedPage,
  }) => {
    const pgpContent =
      '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nname: nginx\nversion: 22.6.10\n-----BEGIN PGP SIGNATURE-----\nwsBcBA==\n-----END PGP SIGNATURE-----';

    await setupHelmRoutes(authenticatedPage, {
      ...helmMetadata,
      has_provenance: true,
      provenance_key_id: 'DEADBEEF',
      provenance_hash_algorithm: 'SHA512',
      provenance_signature_date: '2026-01-01T00:00:00Z',
    });
    await authenticatedPage.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/provenance`,
      (route) =>
        route.fulfill({
          status: 200,
          json: {content: pgpContent},
        }),
    );

    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();
    await sidebar.getByTestId('helm-provenance-link').click();

    const modal = authenticatedPage.getByTestId('helm-provenance-modal');
    await expect(modal).toBeVisible();

    const content = authenticatedPage.getByTestId('helm-provenance-content');
    await expect(content).toContainText('BEGIN PGP SIGNED MESSAGE');
    await expect(content).toContainText('BEGIN PGP SIGNATURE');
    await expect(content).toContainText('name: nginx');
  });

  test('provenance sidebar shows hash algorithm and signature date', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage, {
      ...helmMetadata,
      has_provenance: true,
      provenance_key_id: 'ABCD1234',
      provenance_hash_algorithm: 'SHA512',
      provenance_signature_date: '2026-01-01T00:00:00Z',
    });
    await authenticatedPage.route(
      `**/api/v1/repository/*/*/manifest/${helmDigest}/helm/provenance`,
      (route) =>
        route.fulfill({
          status: 200,
          json: {content: '-----BEGIN PGP SIGNED MESSAGE-----\ntest'},
        }),
    );

    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    const sidebar = authenticatedPage.getByTestId('helm-chart-sidebar').first();

    const provCard = sidebar
      .locator('.pf-v6-c-card')
      .filter({hasText: 'Key ID'})
      .first();
    await expect(provCard).toBeVisible();
    await expect(provCard.getByText('Hash algorithm')).toBeVisible();
    await expect(provCard.getByText('SHA512')).toBeVisible();
    await expect(provCard.getByText('Signed')).toBeVisible();
  });
});

// ============================================================================
// Values Tab: Search / Filter
// ============================================================================

test.describe('Helm Chart Values Search', {tag: ['@tags', '@helm']}, () => {
  test('values search input filters YAML paths and shows suggestions', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await authenticatedPage.getByRole('tab', {name: 'Values'}).click();
    await expect(
      authenticatedPage.getByTestId('helm-values-content'),
    ).toBeVisible();

    const searchInput = authenticatedPage.getByTestId('helm-values-search');
    await expect(searchInput).toBeVisible();

    await searchInput.locator('input').fill('image');
    await expect(
      authenticatedPage.locator('[role="menuitem"]').first(),
    ).toBeVisible();

    await searchInput.locator('input').fill('nonexistent-path-xyz');
    await expect(
      authenticatedPage.getByText('No matching paths'),
    ).toBeVisible();
  });
});

// ============================================================================
// Files Tab: Search / Filter
// ============================================================================

test.describe('Helm Chart Files Search', {tag: ['@tags', '@helm']}, () => {
  test('files search input filters the file tree', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(authenticatedPage);
    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/22.6.10?tab=helmchart',
    );

    await authenticatedPage.getByRole('tab', {name: 'Files'}).click();
    await expect(
      authenticatedPage.getByTestId('helm-file-tree').first(),
    ).toBeVisible();

    const searchInput = authenticatedPage.getByTestId('helm-filetree-search');
    await expect(searchInput).toBeVisible();

    await expect(authenticatedPage.getByText('Chart.yaml')).toBeVisible();
    await expect(authenticatedPage.getByText('values.yaml')).toBeVisible();

    await searchInput.locator('input').fill('deployment');
    await expect(authenticatedPage.getByText('deployment.yaml')).toBeVisible();
    await expect(authenticatedPage.getByText('Chart.yaml')).not.toBeVisible();

    await searchInput.locator('input').fill('nonexistent');
    await expect(
      authenticatedPage.getByText('No files matching your search'),
    ).toBeVisible();
  });
});

// ============================================================================
// Extraction States
// ============================================================================

test.describe(
  'Helm Chart Pending Extraction',
  {tag: ['@tags', '@helm']},
  () => {
    test('shows pending extraction alert', async ({authenticatedPage}) => {
      await setupHelmRoutes(
        authenticatedPage,
        {extraction_status: 'pending'},
        'pending-version',
      );

      await authenticatedPage.goto(
        '/repository/user1/helm-charts/tag/pending-version?tab=helmchart',
      );

      await expect(
        authenticatedPage.getByTestId('helm-pending-alert'),
      ).toBeVisible();
      await expect(
        authenticatedPage.getByText('Metadata extraction is in progress'),
      ).toBeVisible();
    });
  },
);

test.describe('Helm Chart Failed Extraction', {tag: ['@tags', '@helm']}, () => {
  test('shows failed extraction alert with error message', async ({
    authenticatedPage,
  }) => {
    await setupHelmRoutes(
      authenticatedPage,
      {
        extraction_status: 'failed',
        extraction_error: 'Chart.yaml is missing',
      },
      'broken-version',
    );

    await authenticatedPage.goto(
      '/repository/user1/helm-charts/tag/broken-version?tab=helmchart',
    );

    await expect(
      authenticatedPage.getByTestId('helm-failed-alert'),
    ).toBeVisible();
    await expect(
      authenticatedPage.getByText('Chart.yaml is missing'),
    ).toBeVisible();
  });
});

// ============================================================================
// Tags Table: Helm Icon and Popover
// ============================================================================

test.describe('Helm Chart Tags Table', {tag: ['@tags', '@helm']}, () => {
  function setupTagsTableRoutes(page: import('@playwright/test').Page) {
    return Promise.all([
      page.route('**/api/v1/repository/*/*/tag/?*', (route) =>
        route.fulfill({
          status: 200,
          json: {
            tags: [
              {
                name: '22.6.10',
                is_manifest_list: false,
                last_modified: 'Mon, 01 Jan 2026 00:00:00 -0000',
                manifest_digest: helmDigest,
                reversion: false,
                size: 50000,
                start_ts: 1735689600,
                is_helm_chart: true,
              },
              {
                name: 'latest',
                is_manifest_list: false,
                last_modified: 'Mon, 01 Jan 2026 00:00:00 -0000',
                manifest_digest:
                  'sha256:0000000000000000000000000000000000000000000000000000000000000001',
                reversion: false,
                size: 12000,
                start_ts: 1735689600,
                is_helm_chart: false,
              },
            ],
            page: 1,
            has_additional: false,
          },
        }),
      ),
      page.route('**/api/v1/repository/*/*', (route) => {
        const url = new URL(route.request().url());
        if (
          url.pathname.includes('/tag/') ||
          url.pathname.includes('/manifest/')
        ) {
          return route.fallback();
        }
        return route.fulfill({
          status: 200,
          json: {
            namespace: 'user1',
            name: 'helm-charts',
            kind: 'image',
            description: '',
            is_public: false,
            is_organization: false,
            is_starred: false,
            status_token: '',
            trust_enabled: false,
            tag_expiration_s: 1209600,
            is_free_account: true,
            state: 'NORMAL',
            can_write: true,
            can_admin: true,
          },
        });
      }),
    ]);
  }

  test('shows Helm icon on Helm chart tags in the tags table', async ({
    authenticatedPage,
  }) => {
    await setupTagsTableRoutes(authenticatedPage);
    await authenticatedPage.goto('/repository/user1/helm-charts?tab=tags');

    await expect(authenticatedPage.getByText('22.6.10')).toBeVisible();

    const helmLabel = authenticatedPage.getByTestId('helm-chart-label');
    await expect(helmLabel.first()).toBeVisible();
  });

  test('TablePopover renders helm pull command for Helm chart tags', async ({
    authenticatedPage,
  }) => {
    await setupTagsTableRoutes(authenticatedPage);
    await authenticatedPage.goto('/repository/user1/helm-charts?tab=tags');

    await expect(authenticatedPage.getByText('22.6.10')).toBeVisible();

    const helmTagRow = authenticatedPage.locator('tr').filter({
      has: authenticatedPage.getByRole('link', {name: '22.6.10', exact: true}),
    });

    await helmTagRow.locator('td[data-label="Pull"] svg').hover();

    const popover = authenticatedPage.getByTestId('pull-popover');
    await expect(popover).toBeVisible({timeout: 10000});
    await expect(popover).toContainText('Helm Pull');

    const helmPullCopy = authenticatedPage.getByTestId('copy-helm-pull');
    await expect(helmPullCopy).toBeVisible();
    await expect(helmPullCopy.locator('input')).toHaveValue(
      /helm pull oci:\/\/.*\/user1\/helm-charts --version 22\.6\.10/,
    );
  });
});

// ============================================================================
// Helm Repo Index: Settings Page
// ============================================================================

test.describe(
  'Helm Repo Index Settings',
  {tag: ['@repository', '@helm', '@settings']},
  () => {
    function setupHelmRepoRoute(
      page: import('@playwright/test').Page,
      ns: string,
      repoName: string,
      indexConfig: {enabled: boolean; tagPattern: string | null} = {
        enabled: false,
        tagPattern: null,
      },
    ) {
      return page.route(
        `**/api/v1/repository/${ns}/${repoName}/helmrepo`,
        (route) => {
          if (route.request().method() === 'GET') {
            return route.fulfill({status: 200, json: indexConfig});
          }
          if (route.request().method() === 'PUT') {
            return route.fulfill({
              status: 200,
              json: route.request().postDataJSON(),
            });
          }
          return route.fallback();
        },
      );
    }

    test('shows Helm Repository Index tab in settings when feature is enabled', async ({
      authenticatedPage,
      api,
    }) => {
      const repo = await api.repository();
      await setupHelmRepoRoute(authenticatedPage, repo.namespace, repo.name);
      await authenticatedPage.goto(`/repository/${repo.fullName}?tab=settings`);

      const helmTab = authenticatedPage.getByTestId(
        'settings-tab-helmrepoindex',
      );
      await expect(helmTab).toBeVisible({timeout: 10000});
    });

    test('toggle enables the index and shows tag pattern + helm repo add command', async ({
      authenticatedPage,
      api,
    }) => {
      const repo = await api.repository();
      await setupHelmRepoRoute(authenticatedPage, repo.namespace, repo.name, {
        enabled: false,
        tagPattern: null,
      });
      await authenticatedPage.goto(`/repository/${repo.fullName}?tab=settings`);

      const helmTab = authenticatedPage.getByTestId(
        'settings-tab-helmrepoindex',
      );
      await expect(helmTab).toBeVisible({timeout: 10000});
      await helmTab.click({force: true});

      await expect(
        authenticatedPage.getByTestId('helm-repo-index-toggle'),
      ).toBeVisible();

      await expect(
        authenticatedPage.getByTestId('helm-repo-add-command'),
      ).not.toBeVisible();

      await authenticatedPage
        .locator('label[for="helm-repo-index-toggle"]')
        .click();

      await expect(
        authenticatedPage.getByTestId('helm-repo-index-tag-pattern'),
      ).toBeVisible();
      await expect(
        authenticatedPage.getByTestId('helm-repo-add-command'),
      ).toBeVisible();

      const repoAddInput = authenticatedPage
        .getByTestId('helm-repo-add-command')
        .locator('input');
      await expect(repoAddInput).toHaveValue(
        new RegExp(`helm repo add ${repo.name}`),
      );
    });

    test('save button is disabled until changes are made', async ({
      authenticatedPage,
      api,
    }) => {
      const repo = await api.repository();
      await setupHelmRepoRoute(authenticatedPage, repo.namespace, repo.name);
      await authenticatedPage.goto(`/repository/${repo.fullName}?tab=settings`);

      const helmTab = authenticatedPage.getByTestId(
        'settings-tab-helmrepoindex',
      );
      await expect(helmTab).toBeVisible({timeout: 10000});
      await helmTab.click({force: true});

      const saveBtn = authenticatedPage.getByTestId('helm-repo-index-save-btn');
      await expect(saveBtn).toBeVisible();
      await expect(saveBtn).toBeDisabled();

      await authenticatedPage
        .locator('label[for="helm-repo-index-toggle"]')
        .click();
      await expect(saveBtn).toBeEnabled();
    });

    test('info alert about background processing is shown', async ({
      authenticatedPage,
      api,
    }) => {
      const repo = await api.repository();
      await setupHelmRepoRoute(authenticatedPage, repo.namespace, repo.name);
      await authenticatedPage.goto(`/repository/${repo.fullName}?tab=settings`);

      const helmTab = authenticatedPage.getByTestId(
        'settings-tab-helmrepoindex',
      );
      await expect(helmTab).toBeVisible({timeout: 10000});
      await helmTab.click({force: true});

      await expect(
        authenticatedPage.getByTestId('helm-index-info-alert'),
      ).toBeVisible();
      await expect(
        authenticatedPage.getByText('Background processing'),
      ).toBeVisible();
    });

    test('shows pre-filled tag pattern when config has one', async ({
      authenticatedPage,
      api,
    }) => {
      const repo = await api.repository();
      await setupHelmRepoRoute(authenticatedPage, repo.namespace, repo.name, {
        enabled: true,
        tagPattern: '^v[0-9]+\\..*',
      });
      await authenticatedPage.goto(`/repository/${repo.fullName}?tab=settings`);

      const helmTab = authenticatedPage.getByTestId(
        'settings-tab-helmrepoindex',
      );
      await expect(helmTab).toBeVisible({timeout: 10000});
      await helmTab.click({force: true});

      const patternInput = authenticatedPage.getByTestId(
        'helm-repo-index-tag-pattern',
      );
      await expect(patternInput).toBeVisible();
      await expect(patternInput).toHaveValue('^v[0-9]+\\..*');
    });
  },
);

// ============================================================================
// Helm Repo Info Card on Information Page
// ============================================================================

test.describe(
  'Helm Repo Info Card',
  {tag: ['@repository', '@helm', '@information']},
  () => {
    test('shows Helm Repository card with helm repo add command when index is enabled', async ({
      authenticatedPage,
    }) => {
      await authenticatedPage.route(
        '**/api/v1/repository/*/*/helmrepo',
        (route) =>
          route.fulfill({
            status: 200,
            json: {enabled: true, tagPattern: null},
          }),
      );

      await authenticatedPage.route('**/api/v1/repository/*/*', (route) => {
        const url = new URL(route.request().url());
        if (url.pathname.includes('/helmrepo')) {
          return route.fallback();
        }
        return route.fulfill({
          status: 200,
          json: {
            namespace: 'user1',
            name: 'helm-charts',
            kind: 'image',
            description: 'Test repo',
            is_public: false,
            is_organization: false,
            is_starred: false,
            status_token: '',
            trust_enabled: false,
            tag_expiration_s: 1209600,
            is_free_account: true,
            state: 'NORMAL',
            can_write: true,
            can_admin: true,
            stats: [],
          },
        });
      });

      await authenticatedPage.route('**/config', (route) =>
        route.fulfill({
          status: 200,
          json: {
            features: {
              HELM_REPO_INDEX: true,
              HELM_OCI_SUPPORT: true,
              BUILD_SUPPORT: false,
              SECURITY_SCANNER: false,
            },
            config: {
              SERVER_HOSTNAME: 'localhost:8080',
              AUTHENTICATION_TYPE: 'Database',
            },
          },
        }),
      );

      await authenticatedPage.goto('/repository/user1/helm-charts');

      await expect(
        authenticatedPage.getByText('Helm Repository'),
      ).toBeVisible();
      await expect(
        authenticatedPage.getByText(
          'Add this repository as a Helm chart repository',
        ),
      ).toBeVisible();

      const helmRepoCard = authenticatedPage.locator('.pf-v6-c-card').filter({
        hasText: 'Helm Repository',
      });
      await expect(helmRepoCard.locator('input[readonly]').first()).toHaveValue(
        /helm repo add/,
      );
    });

    test('helm repo add command appears alongside description, pull stats, and pull commands', async ({
      authenticatedPage,
      authenticatedRequest,
      csrfToken,
      api,
    }) => {
      const repo = await api.repository();

      await authenticatedRequest.put(
        `${API_URL}/api/v1/repository/${repo.namespace}/${repo.name}`,
        {
          headers: {'X-CSRF-Token': csrfToken},
          data: {description: '**Helm-enabled** repository for testing'},
        },
      );

      await authenticatedPage.route(
        `**/api/v1/repository/${repo.namespace}/${repo.name}/helmrepo`,
        (route) =>
          route.fulfill({
            status: 200,
            json: {enabled: true, tagPattern: null},
          }),
      );

      await authenticatedPage.goto(
        `/repository/${repo.fullName}?tab=information`,
      );

      // Repository Activity card
      await expect(
        authenticatedPage.getByText('Repository Activity'),
      ).toBeVisible();

      // Description card with markdown
      const descriptionCard = authenticatedPage
        .locator('.pf-v6-c-card')
        .filter({hasText: 'Description'});
      await expect(descriptionCard).toBeVisible();
      await expect(descriptionCard.getByText('Helm-enabled')).toBeVisible();

      // Pull Commands card with Podman and Docker commands
      const pullCard = authenticatedPage
        .locator('.pf-v6-c-card')
        .filter({hasText: 'Pull Commands'});
      await expect(pullCard).toBeVisible();
      await expect(
        pullCard.getByText(
          'Pull this container with the following Podman command:',
        ),
      ).toBeVisible();
      await expect(pullCard.locator('input[readonly]').first()).toHaveValue(
        new RegExp(`podman pull.*${repo.namespace}/${repo.name}`),
      );
      await expect(
        pullCard.getByText(
          'Pull this container with the following Docker command:',
        ),
      ).toBeVisible();
      await expect(pullCard.locator('input[readonly]').last()).toHaveValue(
        new RegExp(`docker pull.*${repo.namespace}/${repo.name}`),
      );

      // Helm Repository card with helm repo add command
      const helmRepoCard = authenticatedPage
        .locator('.pf-v6-c-card')
        .filter({hasText: 'Helm Repository'});
      await expect(helmRepoCard).toBeVisible();
      await expect(
        helmRepoCard.getByText(
          'Add this repository as a Helm chart repository',
        ),
      ).toBeVisible();
      await expect(helmRepoCard.locator('input[readonly]').first()).toHaveValue(
        new RegExp(`helm repo add ${repo.name}`),
      );
    });

    test('does not show Helm Repository card when index is disabled', async ({
      authenticatedPage,
    }) => {
      await authenticatedPage.route(
        '**/api/v1/repository/*/*/helmrepo',
        (route) =>
          route.fulfill({
            status: 200,
            json: {enabled: false, tagPattern: null},
          }),
      );

      await authenticatedPage.route('**/api/v1/repository/*/*', (route) => {
        const url = new URL(route.request().url());
        if (url.pathname.includes('/helmrepo')) {
          return route.fallback();
        }
        return route.fulfill({
          status: 200,
          json: {
            namespace: 'user1',
            name: 'helm-charts',
            kind: 'image',
            description: 'Test repo',
            is_public: false,
            is_organization: false,
            is_starred: false,
            status_token: '',
            trust_enabled: false,
            tag_expiration_s: 1209600,
            is_free_account: true,
            state: 'NORMAL',
            can_write: true,
            can_admin: true,
            stats: [],
          },
        });
      });

      await authenticatedPage.route('**/config', (route) =>
        route.fulfill({
          status: 200,
          json: {
            features: {
              HELM_REPO_INDEX: true,
              BUILD_SUPPORT: false,
              SECURITY_SCANNER: false,
            },
            config: {
              SERVER_HOSTNAME: 'localhost:8080',
              AUTHENTICATION_TYPE: 'Database',
            },
          },
        }),
      );

      await authenticatedPage.goto('/repository/user1/helm-charts');

      await expect(authenticatedPage.getByText('Pull Commands')).toBeVisible();
      await expect(
        authenticatedPage.getByText('Helm Repository'),
      ).not.toBeVisible();
    });
  },
);
