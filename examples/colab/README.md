# Colab: VisionGuard360 site graph + agent memory on the hardened fork

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/dhaneshkk/neug/blob/security/review-fixes/examples/colab/neug_vg360_agent_memory.ipynb)

A single-cell notebook that installs this fork's wheel from the
[`fork-wheels`](https://github.com/dhaneshkk/neug/releases/tag/fork-wheels) release
(Linux x86_64, CPython 3.11–3.13, `vector_search` and `fts` bundled) and runs:

1. **Security probes**: `UNINSTALL '../..'` path traversal and `INSTALL ... FROM` an
   unlisted repository are both rejected.
2. **Lean 4 proofs**: transaction atomicity, integer reciprocal-rank-fusion monotonicity,
   2-hop alert monotonicity under inserts, and MCC numerator properties. The real Lean
   compiler checks them, and each has a runtime mirror in the notebook.
3. **VisionGuard360**: a rig → zone → camera → equipment → permit → incident graph with
   *incidents within 2 hops of a hot-work permit* (checked against an independent BFS),
   a zone risk board, atomic camera-detection ingest with injected crashes, and
   detection → past-incident matching (HNSW + graph fusion) scored with MCC.
4. **Agent memory**: entities and relations, episodic embeddings, BM25 keyword recall,
   atomic writes with fact supersession, durability across reopen, and hybrid recall
   scored with MCC.

Text encoders are trained with Sharpness-Aware Minimization (numpy, no GPU needed).

**LLM (Google Gemini by default).** Add a `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) Colab
secret from [Google AI Studio](https://aistudio.google.com/apikey). The notebook calls
Gemini's OpenAI-compatible endpoint `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions`:
- **Model:** it picks the newest stable `gemini-X.Y-flash` listed by `/models`. To pin a
  model, set `CFG["LLM_MODEL"]` or an `LLM_MODEL` secret.
- **Parameters:** it sends `reasoning_effort` and leaves out `temperature`/`top_p`
  (newer Gemini models ignore or reject them).
- **Rate limits:** it retries on HTTP 429/5xx.

The LLM writes the STOP-WORK brief and the memory answer. Set
`CFG["LLM_EXTRACT_PER_EPISODE"]=True` to also use it for entity extraction (about 220
calls, which can hit free-tier limits). To use another OpenAI-compatible server instead,
set `CFG["LLM_PROVIDER"]="openai"` plus an `OPENAI_API_KEY` and an optional
`LLM_BASE_URL`. With no key, the notebook uses offline fallbacks.

All data is synthetic.
