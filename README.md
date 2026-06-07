# ContextAgent

ContextAgent is a prototype for executable external-context construction in smart contract fuzzing. It targets the Environmental Blindness problem: vulnerability-relevant paths in DeFi contracts are often gated by return values from external contracts, while traditional fuzzers mainly mutate transaction inputs and contract-internal state.

The system analyzes path-relevant external calls, derives semantic constraints for their return values, and exports selector-indexed context artifacts. These artifacts package concrete mock return value families for fuzzing:

- `Satisfy`: values that preserve guarded paths.
- `Violate`: values that negate or redirect guarded behavior.
- `Boundary`: values near branch or semantic boundaries.

AMFuzz integrates ContextAgent with a modified ConFuzzius-style runtime. During fuzzing, the runtime looks up generated context artifacts and injects ABI-compatible return bytes at matched external-call sites.

## Installation

This codebase is implemented in Python. The core pinned dependencies are listed in `requirements.txt`.

```bash
pip install -r requirements.txt
```

The prototype also expects Solidity tooling and Slither-compatible analysis dependencies when running the full pipeline.

## Configure LLM Access

ContextAgent can use a remote OpenAI-compatible endpoint or a local model. The default settings are in `utils/settings.py`.

For remote use, set:

```bash
set LLM_API_KEY=your_api_key
```

On Linux/macOS:

```bash
export LLM_API_KEY=your_api_key
```

## Run ContextAgent

For a single Solidity contract:

```bash
python -m context_agent.pipeline \
  --contract path/to/Contract.sol \
  --name ContractName \
  --output path/to/Contract_mock_return_values.json
```

For a directory of contracts:

```bash
python -m context_agent.pipeline \
  --contract path/to/contracts \
  --batch \
  --output-dir path/to/artifacts
```

The output JSON files are selector-indexed external-context artifacts consumed by the fuzzing runtime.
When running AMFuzz, place each generated `*_mock_return_values.json` file next to the corresponding Solidity source file. The current runtime resolves context artifacts from the source directory.

## Run AMFuzz

Run fuzzing from Solidity source:

```bash
python main.py \
  --source path/to/Contract.sol \
  --contract ContractName \
  --timeout 200
```

Useful options include:

- `--solc`: Solidity compiler version.
- `--evm`: EVM version.
- `--output-dir`: directory for JSON result files.

## Data Availability

This repository currently focuses on the prototype implementation. The complete reproduction package, including detailed benchmark metadata, generated artifacts, logs, and reproduction scripts, will be updated after the paper is accepted or the review process is completed.

## More Information

More details will be added soon.
