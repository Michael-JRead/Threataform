#!/usr/bin/env python3
"""
export_vocab.py -- Export sentencepiece vocab to Tokenizer.js format.

Converts the trained .model file to a JSON object that can be passed to
tokenizer.loadVocab(data) in the browser.

Output JSON format:
{
  "merges": [[left, right], ...],  // BPE merge rules in priority order
  "extra":  { "tokenString": id }  // trained vocab tokens
}

Usage:
    python scripts/export_vocab.py \\
        --model   data/vocab/threataform_bpe.model \\
        --output  src/lib/llm/vocab.json

Then in ThreataformEngine.js or at app startup:
    import vocabData from "./vocab.json";
    tokenizer.loadVocab(vocabData);

Requires:
    pip install sentencepiece
"""

import argparse
import json
import os
import sentencepiece as spm


def byte_to_token_str(b):
    """Match the b2s() function in Tokenizer.js."""
    if 0x20 <= b <= 0x7E:
        return chr(b)
    return f"<{b:02X}>"


def export_vocab(model_path, output_path):
    sp = spm.SentencePieceProcessor()
    sp.Load(model_path)

    vocab_size = sp.GetPieceSize()
    print(f"Vocab size: {vocab_size}")

    SPECIAL_LIST = [
        "<|pad|>", "<|begin_of_text|>", "<|end_of_text|>", "<|unk|>",
        "<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>",
        "<|retrieve|>", "<|no_retrieve|>",
        "<|isrel|>", "<|isirrel|>",
        "<|issup|>", "<|isnosup|>",
        "<|isuse|>",
        "<|threat|>", "<|control|>", "<|resource|>", "<|mitre|>",
    ]
    BYTE_OFFSET  = len(SPECIAL_LIST)  # 18
    MERGE_OFFSET = BYTE_OFFSET + 256  # 274

    merges = []
    extra  = {}

    for i in range(vocab_size):
        piece = sp.IdToPiece(i)
        if piece.startswith("<") and piece.endswith(">") and piece in SPECIAL_LIST:
            continue

        decoded = piece.replace("▁", " ")

        if len(decoded) <= 1:
            continue

        assigned_id = MERGE_OFFSET + len(extra)
        extra[decoded] = assigned_id

        for split in range(1, len(decoded)):
            left  = decoded[:split]
            right = decoded[split:]
            if left and right:
                merges.append([left, right])
                break

    data = {"merges": merges, "extra": extra}

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

    print(f"Exported {len(merges)} merge rules and {len(extra)} extra tokens -> {output_path}")
    print("In the app, call: tokenizer.loadVocab(vocabData)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model",  default="data/vocab/threataform_bpe.model")
    ap.add_argument("--output", default="src/lib/llm/vocab.json")
    args = ap.parse_args()

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    export_vocab(args.model, args.output)


if __name__ == "__main__":
    main()