# petfish-style-rewriter

This skill rewrites text into Petfish's structured technical writing style.

For long outputs, run:

```bash
uv run scripts/normalize_text.py --file draft.md --output draft.normalized.md
uv run scripts/style_check.py --file draft.normalized.md
```
