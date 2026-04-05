import React, {useState, useMemo, useCallback, useEffect, useRef} from 'react';
import {
  Alert,
  Flex,
  FlexItem,
  Menu,
  MenuContent,
  MenuItem,
  MenuList,
  SearchInput,
  Spinner,
} from '@patternfly/react-core';
import {CodeEditor, Language} from '@patternfly/react-code-editor';
import type {editor as MonacoEditor} from 'monaco-editor';
import type Monaco from 'monaco-editor';
import {useHelmValues} from 'src/hooks/UseHelmChart';
import {useTheme} from 'src/contexts/ThemeContext';

interface YamlPath {
  path: string;
  line: number;
}

function extractYamlPaths(yamlText: string): YamlPath[] {
  const paths: YamlPath[] = [];
  const lines = yamlText.split('\n');
  const stack: {indent: number; key: string}[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();

    if (!trimmed || trimmed.startsWith('#')) continue;

    const indent = line.length - trimmed.length;
    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*:/);
    if (!match) continue;

    const key = match[1];

    while (stack.length > 0 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    stack.push({indent, key});
    const fullPath = stack.map((s) => s.key).join('.');
    paths.push({path: fullPath, line: i + 1});
  }

  return paths;
}

export default function HelmChartValuesTab(props: HelmChartValuesTabProps) {
  const {isDarkTheme} = useTheme();
  const [searchValue, setSearchValue] = useState('');
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const suggestionsRef = useRef<HTMLDivElement>(null);
  const editorRef = useRef<MonacoEditor.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<typeof Monaco | null>(null);
  const decorationsRef =
    useRef<MonacoEditor.IEditorDecorationsCollection | null>(null);
  const highlightTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const {
    data: values,
    isLoading,
    isError,
  } = useHelmValues(props.org, props.repo, props.digest);

  const yamlPaths = useMemo(() => {
    if (!values) return [];
    return extractYamlPaths(values);
  }, [values]);

  const filteredPaths = useMemo(() => {
    if (!searchValue.trim()) return yamlPaths;
    const lower = searchValue.toLowerCase();
    return yamlPaths.filter((p) => p.path.toLowerCase().includes(lower));
  }, [yamlPaths, searchValue]);

  const scrollToLine = useCallback((lineNumber: number) => {
    setShowSuggestions(false);
    setSearchValue('');
    setActiveIndex(-1);

    const editor = editorRef.current;
    if (!editor) return;

    editor.revealLineInCenter(lineNumber, 0);

    if (decorationsRef.current) {
      decorationsRef.current.clear();
    }
    decorationsRef.current = editor.createDecorationsCollection([
      {
        range: {
          startLineNumber: lineNumber,
          startColumn: 1,
          endLineNumber: lineNumber,
          endColumn: 1,
        },
        options: {
          isWholeLine: true,
          className: 'helm-values-highlight-line',
          overviewRuler: {
            color: 'var(--pf-t--global--color--brand--default)',
            position: 1,
          },
        },
      },
    ]);

    if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = setTimeout(() => {
      if (decorationsRef.current) {
        decorationsRef.current.clear();
      }
    }, 3000);
  }, []);

  const handleSearchKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!showSuggestions || filteredPaths.length === 0) {
        if (e.key === 'Enter' && filteredPaths.length > 0) {
          scrollToLine(filteredPaths[0].line);
        }
        return;
      }

      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setActiveIndex((prev) =>
            prev < filteredPaths.length - 1 ? prev + 1 : 0,
          );
          break;
        case 'ArrowUp':
          e.preventDefault();
          setActiveIndex((prev) =>
            prev > 0 ? prev - 1 : filteredPaths.length - 1,
          );
          break;
        case 'Enter':
          e.preventDefault();
          if (activeIndex >= 0 && activeIndex < filteredPaths.length) {
            scrollToLine(filteredPaths[activeIndex].line);
          } else if (filteredPaths.length > 0) {
            scrollToLine(filteredPaths[0].line);
          }
          break;
        case 'Escape':
          e.preventDefault();
          setShowSuggestions(false);
          setActiveIndex(-1);
          break;
      }
    },
    [showSuggestions, filteredPaths, activeIndex, scrollToLine],
  );

  useEffect(() => {
    if (activeIndex >= 0 && suggestionsRef.current) {
      const active = suggestionsRef.current.querySelector(
        `[data-index="${activeIndex}"]`,
      );
      if (active) {
        active.scrollIntoView({block: 'nearest'});
      }
    }
  }, [activeIndex]);

  const handleEditorDidMount = useCallback(
    (editor: MonacoEditor.IStandaloneCodeEditor, monaco: typeof Monaco) => {
      editorRef.current = editor;
      monacoRef.current = monaco;

      const pfBg = getComputedStyle(document.documentElement)
        .getPropertyValue('--pf-t--global--background--color--primary--default')
        .trim();

      monaco.editor.defineTheme('pf-light', {
        base: 'vs',
        inherit: true,
        rules: [],
        colors: pfBg ? {'editor.background': pfBg} : {},
      });

      monaco.editor.defineTheme('pf-dark', {
        base: 'vs-dark',
        inherit: true,
        rules: [],
        colors: pfBg ? {'editor.background': pfBg} : {},
      });

      monaco.editor.setTheme(isDarkTheme ? 'pf-dark' : 'pf-light');
    },
    [isDarkTheme],
  );

  useEffect(() => {
    const monaco = monacoRef.current;
    if (!monaco) return;

    const pfBg = getComputedStyle(document.documentElement)
      .getPropertyValue('--pf-t--global--background--color--primary--default')
      .trim();

    monaco.editor.defineTheme('pf-light', {
      base: 'vs',
      inherit: true,
      rules: [],
      colors: pfBg ? {'editor.background': pfBg} : {},
    });

    monaco.editor.defineTheme('pf-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [],
      colors: pfBg ? {'editor.background': pfBg} : {},
    });

    monaco.editor.setTheme(isDarkTheme ? 'pf-dark' : 'pf-light');
  }, [isDarkTheme]);

  if (isLoading) {
    return <Spinner size="lg" aria-label="Loading values.yaml" />;
  }

  if (isError || !values) {
    return <Alert variant="info" title="values.yaml not available" isInline />;
  }

  const lineCount = values.split('\n').length;
  const editorHeight = `${Math.min(Math.max(lineCount * 19, 300), 700)}px`;

  return (
    <>
      <style>{`
        .helm-values-highlight-line {
          background-color: var(--pf-t--global--color--status--info--default) !important;
          transition: background-color 0.3s ease;
        }
        .helm-values-editor .pf-v6-c-code-editor__header-content,
        .helm-values-editor .pf-v6-c-code-editor__tab,
        .helm-values-editor .pf-v6-c-code-editor__main {
          background-color: var(--pf-t--global--background--color--primary--default);
        }
      `}</style>
      <div
        style={{
          position: 'relative',
          zIndex: 100,
          marginBottom: 'var(--pf-t--global--spacer--sm)',
        }}
      >
        <SearchInput
          placeholder="Search paths... e.g. server.ingress.enabled"
          value={searchValue}
          onChange={(_e, value) => {
            setSearchValue(value);
            setShowSuggestions(value.length > 0);
            setActiveIndex(-1);
          }}
          onFocus={() => {
            if (searchValue) setShowSuggestions(true);
          }}
          onClear={() => {
            setSearchValue('');
            setShowSuggestions(false);
            setActiveIndex(-1);
          }}
          onKeyDown={handleSearchKeyDown}
          aria-label="Search YAML paths"
          data-testid="helm-values-search"
        />

        {showSuggestions && filteredPaths.length > 0 && (
          <div
            ref={suggestionsRef}
            style={{position: 'absolute', left: 0, right: 0, zIndex: 101}}
          >
            <Menu
              isScrollable
              style={{
                maxHeight: '220px',
                boxShadow: 'var(--pf-t--global--box-shadow--md)',
              }}
            >
              <MenuContent>
                <MenuList>
                  {filteredPaths.slice(0, 50).map((p, idx) => (
                    <MenuItem
                      key={p.path}
                      data-index={idx}
                      isFocused={idx === activeIndex}
                      onClick={() => scrollToLine(p.line)}
                    >
                      <Flex
                        justifyContent={{
                          default: 'justifyContentSpaceBetween',
                        }}
                      >
                        <FlexItem>
                          <span
                            style={{
                              fontFamily:
                                'var(--pf-t--global--font--family--mono)',
                            }}
                          >
                            {p.path}
                          </span>
                        </FlexItem>
                        <FlexItem>
                          <span
                            style={{
                              fontSize: 'var(--pf-t--global--font--size--xs)',
                              color: 'var(--pf-t--global--text--color--subtle)',
                            }}
                          >
                            :{p.line}
                          </span>
                        </FlexItem>
                      </Flex>
                    </MenuItem>
                  ))}
                </MenuList>
              </MenuContent>
            </Menu>
          </div>
        )}

        {showSuggestions && searchValue && filteredPaths.length === 0 && (
          <div style={{position: 'absolute', left: 0, right: 0, zIndex: 101}}>
            <Menu>
              <MenuContent>
                <MenuList>
                  <MenuItem isDisabled>No matching paths</MenuItem>
                </MenuList>
              </MenuContent>
            </Menu>
          </div>
        )}
      </div>

      <div data-testid="helm-values-content" className="helm-values-editor">
        <CodeEditor
          code={values}
          language={Language.yaml}
          isDarkTheme={isDarkTheme}
          isReadOnly
          isLineNumbersVisible
          isCopyEnabled
          height={editorHeight}
          onEditorDidMount={handleEditorDidMount}
          options={{
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            minimap: {enabled: false},
            folding: true,
            renderLineHighlight: 'none',
            smoothScrolling: true,
          }}
        />
      </div>
    </>
  );
}

type HelmChartValuesTabProps = {
  org: string;
  repo: string;
  digest: string;
};
