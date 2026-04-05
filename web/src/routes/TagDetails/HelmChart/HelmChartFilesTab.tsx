import React, {useState, useMemo} from 'react';
import {SearchInput, TreeView, TreeViewDataItem} from '@patternfly/react-core';
import {FileIcon, FolderOpenIcon} from '@patternfly/react-icons';
import prettyBytes from 'pretty-bytes';

interface FileEntry {
  path: string;
  size: number;
}

interface TreeNode {
  name: string;
  size?: number;
  children: Map<string, TreeNode>;
}

function buildTree(files: FileEntry[]): TreeNode {
  const root: TreeNode = {name: '', children: new Map()};

  for (const file of files) {
    const parts = file.path.split('/');
    let current = root;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (!current.children.has(part)) {
        current.children.set(part, {name: part, children: new Map()});
      }
      current = current.children.get(part)!;
      if (i === parts.length - 1) {
        current.size = file.size;
      }
    }
  }

  return root;
}

function treeNodeToViewData(node: TreeNode): TreeViewDataItem {
  const children = Array.from(node.children.values());
  const label =
    node.size !== undefined
      ? `${node.name} (${prettyBytes(node.size)})`
      : node.name;

  const isDir = children.length > 0;
  const item: TreeViewDataItem = {
    name: label,
    id: node.name,
    icon: isDir ? <FolderOpenIcon /> : <FileIcon />,
  };

  if (isDir) {
    item.children = children.map(treeNodeToViewData);
    item.defaultExpanded = true;
  }

  return item;
}

export default function HelmChartFilesTab(props: HelmChartFilesTabProps) {
  const [searchValue, setSearchValue] = useState('');

  const treeData = useMemo(() => {
    let files = props.fileTree;

    if (searchValue.trim()) {
      const lower = searchValue.toLowerCase();
      files = files.filter((f) => {
        const segments = f.path.toLowerCase().split('/');
        return segments.some((seg) => seg.includes(lower));
      });
    }

    const root = buildTree(files);
    return Array.from(root.children.values()).map(treeNodeToViewData);
  }, [props.fileTree, searchValue]);

  if (!props.fileTree || props.fileTree.length === 0) {
    return <p>No files available.</p>;
  }

  return (
    <>
      <div style={{marginBottom: 'var(--pf-t--global--spacer--sm)'}}>
        <SearchInput
          placeholder="Filter files..."
          value={searchValue}
          onChange={(_e, value) => setSearchValue(value)}
          onClear={() => setSearchValue('')}
          aria-label="Filter file tree"
          data-testid="helm-filetree-search"
        />
      </div>
      {treeData.length > 0 ? (
        <TreeView
          data={treeData}
          hasGuides
          aria-label="Helm chart file tree"
          data-testid="helm-file-tree"
        />
      ) : (
        <p>No files matching your search.</p>
      )}
    </>
  );
}

type HelmChartFilesTabProps = {
  fileTree: {path: string; size: number}[];
};
