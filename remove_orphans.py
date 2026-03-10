import sys
import io

# Force stdout to utf-8 so print works with box-drawing chars
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

filepath = r"C:\Users\mjrma\Downloads\threataform\terraform-enterprise-intelligence.jsx"

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

original_len = len(content.splitlines())
print(f"Original: {original_len} lines")

def find_block_end(content, start_idx):
    i = start_idx
    while i < len(content) and content[i] != '{':
        i += 1
    if i >= len(content):
        return -1
    brace_depth = 1
    i += 1
    while i < len(content) and brace_depth > 0:
        ch = content[i]
        if ch == '{':
            brace_depth += 1
        elif ch == '}':
            brace_depth -= 1
        i += 1
    return i

orphaned_blocks = [
    "        {/* \u2500\u2500 THREAT FINDINGS TAB \u2500\u2500 */}",
    "        {/* \u2500\u2500 SCOPE ANALYSIS TAB \u2500\u2500 */}",
    "        {/* \u2500\u2500 MISCONFIG CHECKS TAB \u2500\u2500 */}",
    "        {/* \u2500\u2500 ATT&CK MAPPING TAB \u2500\u2500 */}",
    "        {/* \u2500\u2500 SECURITY POSTURE TAB \u2500\u2500 */}",
    "        {/* \u2500\u2500 CONTROL INVENTORY TAB \u2500\u2500 */}",
]

removed_count = 0
for comment in orphaned_blocks:
    idx = content.find(comment)
    if idx == -1:
        print(f"  WARNING: Comment not found: {comment}")
        continue

    line_start = content.rfind('\n', 0, idx)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    itab_start = content.find('{iTab===', idx)
    if itab_start == -1:
        print(f"  WARNING: No iTab block found after comment: {comment}")
        continue

    block_end = find_block_end(content, itab_start)
    if block_end == -1:
        print(f"  WARNING: Could not find block end for: {comment}")
        continue

    while block_end < len(content) and content[block_end] in ('\n', '\r'):
        block_end += 1

    removed = content[line_start:block_end]
    removed_lines = removed.count('\n')

    print(f"  Removing: {comment.strip()}")
    print(f"    Lines removed: {removed_lines}")
    print(f"    First 80 chars of removed block: {removed[:80]!r}")

    content = content[:line_start] + content[block_end:]
    removed_count += removed_lines

print(f"\nRemoved {removed_count} total lines across {len(orphaned_blocks)} blocks")
print(f"New length: {len(content.splitlines())} lines")

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("Done. File written successfully.")
