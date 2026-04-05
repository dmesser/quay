import React from 'react';
import {
  Alert,
  CodeBlock,
  CodeBlockAction,
  CodeBlockCode,
  ClipboardCopyButton,
  Modal,
  ModalBody,
  ModalHeader,
  ModalVariant,
  Spinner,
} from '@patternfly/react-core';
import {useHelmProvenance} from 'src/hooks/UseHelmChart';

export default function HelmChartProvenanceModal(
  props: HelmChartProvenanceModalProps,
) {
  const [copied, setCopied] = React.useState(false);
  const {
    data: provenance,
    isLoading,
    isError,
  } = useHelmProvenance(props.org, props.repo, props.digest);

  return (
    <Modal
      variant={ModalVariant.large}
      isOpen={props.isOpen}
      onClose={props.onClose}
      aria-label="Provenance data"
      data-testid="helm-provenance-modal"
    >
      <ModalHeader title="Provenance" />
      <ModalBody>
        {isLoading && <Spinner size="lg" aria-label="Loading provenance" />}
        {isError && (
          <Alert
            variant="info"
            title="Provenance data not available"
            isInline
          />
        )}
        {provenance && (
          <CodeBlock
            actions={
              <CodeBlockAction>
                <ClipboardCopyButton
                  id="helm-provenance-modal-copy"
                  textId="helm-provenance-modal-code"
                  aria-label="Copy provenance"
                  onClick={() => {
                    navigator.clipboard.writeText(provenance);
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
            <CodeBlockCode
              id="helm-provenance-modal-code"
              data-testid="helm-provenance-content"
            >
              {provenance}
            </CodeBlockCode>
          </CodeBlock>
        )}
      </ModalBody>
    </Modal>
  );
}

type HelmChartProvenanceModalProps = {
  isOpen: boolean;
  onClose: () => void;
  org: string;
  repo: string;
  digest: string;
};
