import React from 'react';
import {
  Alert,
  CodeBlock,
  CodeBlockAction,
  CodeBlockCode,
  ClipboardCopyButton,
  Content,
  Spinner,
} from '@patternfly/react-core';
import {Table, Th, Td} from '@patternfly/react-table';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import rehypeSanitize from 'rehype-sanitize';
import {useHelmReadme} from 'src/hooks/UseHelmChart';

function MarkdownCodeBlock(props: {code: string}) {
  const [copied, setCopied] = React.useState(false);

  return (
    <CodeBlock
      actions={
        <CodeBlockAction>
          <ClipboardCopyButton
            id="helm-readme-copy"
            textId="helm-readme-code"
            aria-label="Copy to clipboard"
            onClick={() => {
              navigator.clipboard.writeText(props.code);
              setCopied(true);
            }}
            exitDelay={copied ? 1500 : 600}
            maxWidth="110px"
            variant="plain"
            onTooltipHidden={() => setCopied(false)}
          >
            {copied ? 'Copied!' : 'Copy'}
          </ClipboardCopyButton>
        </CodeBlockAction>
      }
    >
      <CodeBlockCode>{props.code}</CodeBlockCode>
    </CodeBlock>
  );
}

export default function HelmChartReadme(props: HelmChartReadmeProps) {
  const {
    data: readme,
    isLoading,
    isError,
  } = useHelmReadme(props.org, props.repo, props.digest);

  if (isLoading) {
    return <Spinner size="lg" aria-label="Loading README" />;
  }

  if (isError || !readme) {
    return (
      <Alert variant="info" title="No README available" isInline isPlain />
    );
  }

  return (
    <Content data-testid="helm-readme-content">
      <Markdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[[rehypeRaw], [rehypeSanitize]]}
        components={{
          code({children}) {
            const text =
              typeof children === 'string' ? children : String(children);
            const isInline = !text.includes('\n');
            return isInline ? (
              <code>{children}</code>
            ) : (
              <MarkdownCodeBlock code={text} />
            );
          },
          table: ({children}) => (
            <Table borders={true} variant="compact">
              {children}
            </Table>
          ),
          th: ({children}) => (
            <Th
              style={{
                border: '1px solid var(--pf-t--global--border--color--default)',
                padding: '8px',
              }}
            >
              {children}
            </Th>
          ),
          td: ({children}) => (
            <Td
              style={{
                border: '1px solid var(--pf-t--global--border--color--default)',
                padding: '8px',
              }}
            >
              {children}
            </Td>
          ),
        }}
      >
        {readme}
      </Markdown>
    </Content>
  );
}

type HelmChartReadmeProps = {
  org: string;
  repo: string;
  digest: string;
};
