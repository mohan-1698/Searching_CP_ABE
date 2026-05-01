# Mock ABE / Searchable Encryption Benchmark

This project is a mock implementation of the full flow you described:

Setup -> KeyGen -> Encrypt -> Index -> Trapdoor -> Search -> Partial Decrypt -> Final Decrypt

It does not implement blockchain, secure Pedersen commitments, or real pairings.
Instead, it uses a clean exponent-space mock so you can benchmark the math flow and generate graphs.

## What it generates

The benchmark script produces averaged timings and plots for:

- time vs attributes
- time vs keywords
- encrypted text vs keywords
- index vs time
- trapdoor vs time
- sum vs time

It also saves a CSV file with raw averaged timings for each interval.

## Run

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the benchmark:

```bash
python3 run.py --output outputs
```

Example with custom inputs:

```bash
python3 run.py \
  --attributes-count 8 \
  --keywords kw1,kw2,kw3,kw4 \
  --message "This is a sample file for the mock flow." \
  --attr-start 2 --attr-stop 20 --attr-step 2 \
  --keyword-start 2 --keyword-stop 20 --keyword-step 2 \
  --text-start 128 --text-stop 1024 --text-step 128 \
  --cycles 5 \
  --repeats-per-cycle 25 \
  --output outputs
```

## Output files

The plots are saved in the output directory as PNG files.
The raw benchmark data is saved as CSV.

## Extra graph ideas

Useful follow-up graphs you may want later:

- setup time vs attributes
- encryption stage breakdown by percentage
- ciphertext size vs text length
- memory usage vs input size
- search success rate vs keyword count
- end-to-end time before and after smoothing
