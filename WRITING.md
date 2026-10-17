# Writing posts and blue team labs

All articles live in `content/posts/`. The `section` field chooses where an article appears:

- `section: "posts"`: CTF write-up at `/posts/<slug>/` (default for existing articles).
- `section: "blue"`: blue team lab at `/blue/<slug>/`.

Archive combines both sections by `publishDate`, newest first, grouped by year. Drafts appear locally with a Draft label and are excluded from production builds, search, RSS and Archive.

Example: create `content/posts/my-first-lab/index.md`:

```markdown
---
title: "My first blue team lab"
description: "Investigating suspicious activity and documenting the evidence."
publishDate: "2026-10-17"
section: "blue"
tags: ["blue-team", "forensics"]
draft: true
coverImage:
  src: "./cover.jpg"
  alt: "Evidence from the investigation"
---

## Investigation

Write your lab here.
```

Place `cover.jpg` next to `index.md`, or remove the entire `coverImage` block to use the built-in card illustration. Use `section: "posts"` for a CTF write-up. Set `draft: false` when ready to publish.

Run `npm run dev` to preview changes. Run `npm run build` before deployment.
The real domain still needs to be set in `src/site.config.ts` before publishing.
