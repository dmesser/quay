import {test, expect} from '../../fixtures';
import {TEST_USERS} from '../../global-setup';
import {ApiClient} from '../../utils/api';
import {pushImage} from '../../utils/container';

test.describe(
  'Tag List - Build Date Column',
  {tag: ['@tags', '@container']},
  () => {
    let testRepo: {namespace: string; name: string; fullName: string};

    test.beforeAll(async ({userContext, cachedContainerAvailable}) => {
      if (!cachedContainerAvailable) return;

      const api = new ApiClient(userContext.request);

      const repoName = `build-date-test-${Date.now()}`;
      await api.createRepository(TEST_USERS.user.username, repoName, 'private');

      testRepo = {
        namespace: TEST_USERS.user.username,
        name: repoName,
        fullName: `${TEST_USERS.user.username}/${repoName}`,
      };

      await pushImage(testRepo.fullName, 'latest');
    });

    test('displays Build Date column header', async ({authenticatedPage}) => {
      await authenticatedPage.goto(`/repository/${testRepo.fullName}?tab=tags`);
      const header = authenticatedPage.getByText('Build Date');
      await expect(header).toBeVisible();
    });

    test('displays build date for pushed images', async ({
      authenticatedPage,
    }) => {
      await authenticatedPage.goto(`/repository/${testRepo.fullName}?tab=tags`);
      const buildDateCells = authenticatedPage.locator(
        '[data-testid="build-date"]',
      );
      await expect(buildDateCells.first()).toBeVisible();
    });
  },
);
