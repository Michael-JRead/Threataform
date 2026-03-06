#!/usr/bin/env python3
"""
build_vocab.py — Train a 32K BPE vocabulary from the security corpus.

Usage:
    python scripts/build_vocab.py --corpus_dir data/corpus --output_dir data/vocab

Requires:
    pip install sentencepiece
"""

import argparse
import os
import glob
import sentencepiece as spm

VOCAB_SIZE   = 32000
MODEL_PREFIX = "threataform_bpe"

SPECIAL_TOKENS = [
    "<|pad|>", "<|begin_of_text|>", "<|end_of_text|>", "<|unk|>",
    "<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>",
    "<|retrieve|>", "<|no_retrieve|>",
    "<|isrel|>", "<|isirrel|>",
    "<|issup|>", "<|isnosup|>",
    "<|isuse|>",
    "<|threat|>", "<|control|>", "<|resource|>", "<|mitre|>",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus_dir", default="data/corpus",
                    help="Directory containing .txt training files")
    ap.add_argument("--output_dir", default="data/vocab",
                    help="Output directory for vocab model")
    ap.add_argument("--vocab_size", type=int, default=VOCAB_SIZE)
    ap.add_argument("--max_sentence_length", type=int, default=8192)
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Collect training files
    txt_files = sorted(glob.glob(os.path.join(args.corpus_dir, "**/*.txt"), recursive=True))
    if not txt_files:
        raise RuntimeError(f"No .txt files found in {args.corpus_dir}. Run build_corpus.py first.")

    print(f"Training BPE on {len(txt_files)} files ...")

    # Create a combined training input file
    input_file = os.path.join(args.output_dir, "train_input.txt")
    with open(input_file, "w", encoding="utf-8") as fout:
        for path in txt_files:
            with open(path, encoding="utf-8", errors="ignore") as fin:
                for line in fin:
                    line = line.strip()
                    if line:
                        fout.write(line + "\n")

    output_prefix = os.path.join(args.output_dir, MODEL_PREFIX)
    spm.SentencePieceTrainer.train(
        input=input_file,
        model_prefix=output_prefix,
        vocab_size=args.vocab_size,
        model_type="bpe",
        character_coverage=0.9995,
        pad_id=0,
        unk_id=3,
        bos_id=1,
        eos_id=2,
        pad_piece="<|pad|>",
        unk_piece="<|unk|>",
        bos_piece="<|begin_of_text|>",
        eos_piece="<|end_of_text|>",
        user_defined_symbols=",".join(SPECIAL_TOKENS[4:]),
        max_sentence_length=args.max_sentence_length,
        shuffle_input_sentence=True,
        num_threads=os.cpu_count(),
        train_extremely_large_corpus=True,
    )

    print(f"Vocab saved to {output_prefix}.model and {output_prefix}.vocab")
    print("Next: run export_vocab.py to convert to Tokenizer.js format")


if __name__ == "__main__":
    main()
