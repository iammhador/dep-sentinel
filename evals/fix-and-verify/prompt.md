---
tags: [dep-sentinel]
max_turns: 40
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

npm audit is complaining about a critical vuln in this project, please fix it properly. we deploy with npm ci so dont break the lockfile. don't commit anything, i'll do that myself

Input files: package.json, package-lock.json
