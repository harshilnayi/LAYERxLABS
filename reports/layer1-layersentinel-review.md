# LayerSentinel Review

This review is meant as a straight handoff note for the Layer 1 project before it gets folded into `NetScope`.

## Short Verdict

`LayerSentinel` is not just a wrapper.

It already has real project substance:

- custom Nmap XML parsing
- baseline-aware device matching
- scoring and classification logic
- multiple report outputs
- basic automated tests

That said, it is not ready to be called finished yet. There is one core logic problem that undercuts the live-scan story, plus a couple of presentation issues that make the repo feel less personal than it should.

## What Is Already Good

- The code is split into sensible modules instead of one giant script.
- The project does more than run `nmap` and print raw output.
- The reporting layer is genuinely useful for a resume demo.
- Tests exist and pass, which already puts it ahead of a lot of student security repos.

## Findings That Need Attention

### 1. Live scan flags do not match the advertised behavior

File: `rogue_device_detector/nmap_runner.py:12-25`

The default command uses:

```python
DEFAULT_NMAP_ARGS = ["-sn", "-O", "-sV"]
```

That is a real problem. According to the official Nmap reference, `-sn` means "no port scan". The README currently says the project does host discovery and service fingerprinting, and the analyzer also expects port and service data.

Reference: https://nmap.org/book/man-host-discovery.html

Why this matters:

- the live scan path will not reliably produce the port evidence the project scores
- the README promise and the actual command do not line up
- anyone experienced with Nmap may catch this quickly

Priority: must-fix before calling the project complete.

## 2. Packaging metadata hurts authenticity

File: `pyproject.toml:11`

The package author is listed as `OpenAI Codex`.

That might sound small, but it works against the exact thing this repo needs most: trust. If this project is meant to help on a resume, the metadata should point to the real owner or the actual collaborators.

Priority: fix before public sharing.

## 3. Install story is a little sloppy

Files:

- `README.md:24-29`
- `requirements.txt`

The README tells people to install from `requirements.txt`, but the file is empty. The project still works because the package metadata also declares no dependencies, but it leaves a rough edge in the first-run experience.

Priority: low, but easy cleanup.

## Recommendation

I would not throw this project away.

It already has the bones of a strong Layer 1 piece. The right move is to tighten it and then rebrand the improved version as `NetScope` inside this repo.

## Suggested Next Moves

1. Fix the Nmap scan profile so live scans actually support the scoring logic.
2. Replace package metadata with the real author names.
3. Clean up the install flow and make the README feel more personal.
4. Add one or two more tests around live-scan argument construction and baseline matching.

## Bottom Line

The current repo is credible as an early project, but not polished enough to be called final.

If the live-scan flag issue gets fixed, the project can absolutely become a solid resume entry instead of looking like a thin wrapper.
