/**
 * useParseResult — Terraform parse state management
 *
 * Manages:
 *   - files array (parsed TF/HCL/sentinel/tfvars files)
 *   - parseResult (output of parseTFMultiFile)
 *   - xml (current mxGraphModel XML string for DFD)
 *
 * reparse() and readFiles() callbacks depend on many App-level refs
 * and remain in App, but use the setters exposed here.
 */
import { useState } from 'react';

export function useParseResult() {
  const [files, setFiles] = useState([]);
  const [parseResult, setParseResult] = useState(null);
  const [xml, setXml] = useState('');

  return { files, setFiles, parseResult, setParseResult, xml, setXml };
}
