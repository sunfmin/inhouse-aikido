# A Target is a durable asset, not a revision

Findings hang off the GitHub repo or the image repo, so they survive when `main` moves. A Scan is one Engine, one Target, one Revision. A lockfile line is where a Finding points, not what the Target is. We rejected revision-as-Target (Findings would die every commit) and manifest-line-as-Target (inventory becomes a package database).
