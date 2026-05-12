# CP-ABE + Searchable Encryption: Practical Flow and Mock Implementation

This repository contains a complete end-to-end pipeline:

Setup -> KeyGen -> Encrypt -> Index -> Trapdoor -> Search -> Partial Decrypt -> Final Decrypt

It includes:
- practical algorithm explanation (what each symbol means, where it is used)
- step-by-step computations
- runnable scripts for benchmark graphs and end-to-end file demo
- a mock exponent-space implementation (not production cryptography)

## 1) Notation Glossary (Practical Meaning, Usage, Where Used)

### Core domains
- $\mathbb{Z}_p$: field of integers modulo a large prime $p$.
  - How taken: random scalars are sampled uniformly from this field.
  - Used for all exponents and polynomial coefficients.
  - Used in: Setup, KeyGen, Encrypt, Partial/Final decryption.

- $G_1, G_T$: source and target groups for bilinear pairing.
  - How taken: fixed cyclic groups in a pairing-friendly curve setting.
  - Used to represent public values and pairing outputs.
  - Used in: all cryptographic equations.

- $g$: generator of $G_1$.
  - How taken: fixed system parameter at setup.
  - Used to build group elements like $g^x$.
  - Used in: Setup, KeyGen, Encrypt, Search relations.

- $e(\cdot,\cdot)$: bilinear pairing map $G_1 \times G_1 \to G_T$.
  - Practical role: enables cancelation and algebraic consistency checks in decrypt/search.
  - Used in: search test and decryption derivation.

### Setup symbols
- $\gamma_i$: node-local secret sampled by each setup node.
- $\gamma = \sum_i \gamma_i$: aggregated master component.
  - How taken: random + additive aggregation.
  - Used to bind setup with user key and encryption randomness.
  - Used in: Setup output, Encrypt, Partial/Final decrypt.

### User key symbols
- $k$: user secret scalar.
- $U = g^k$: user public-like exponent form.
- $K_{trans} = g^{\gamma + k}$: transformation key for partial decrypt.
- For each attribute $x$:
  - $t_x$: randomizer for attribute component.
  - $H_1(x)$: hash-to-scalar of attribute label.
  - $K_x, L_x$: attribute key components.
  - Used in: policy satisfaction and decryption consistency.

### Encryption symbols
- $r$: encryption randomness.
- $s$: policy secret; in this implementation, $s := r$ to preserve required cancellation.
- $\lambda_i$: policy share values from secret-sharing/LSSS.
- $C_0 = g^r$.
- $Z = e(g,g)^{\gamma r}$.
- $K_{sym} = H_3(C_0 \| Z)$: symmetric key derivation.
- $C_{file} = M \oplus K_{sym}$: encrypted bytes.
- $\tau = H_4(K_{sym} \| C_{file} \| Z)$: integrity tag.

### Searchable encryption symbols
- Keywords $w_j$.
- $H_2(w_j)$: hash-to-scalar per keyword.
- $\Phi = \sum_j H_2(w_j)$.
- Index values: $I_1, I_2$.
- Trapdoor values: $T_1, T_2$.
- Search condition checks pairing-based relation for keyword match.

## 2) Practical End-to-End Flow (Before Mock Details)

### Step A: Setup
1. Multiple authorities generate $\gamma_i$.
2. Aggregate to global $\gamma$.
3. Publish public parameters and keep authority-level secrets protected.

### Step B: User Key Generation
1. User receives attributes from policy authority.
2. Sample user secret $k$.
3. Compute $K_{trans} = g^{\gamma+k}$ and attribute components $(K_x, L_x)$ for each assigned attribute.

### Step C: Encrypt Data + Build Search Index
1. Sample $r$, set $s := r$.
2. Secret-share $s$ into policy shares $\lambda_i$.
3. Compute:
   - $C_0 = g^r$
   - $Z = e(g,g)^{\gamma r}$
   - $K_{sym} = H_3(C_0\|Z)$
   - $C_{file} = M \oplus K_{sym}$
   - $\tau = H_4(K_{sym}\|C_{file}\|Z)$
4. Build searchable index from keywords using $H_2$ and randomizers.

### Step D: Query (Trapdoor) and Search
1. Querier chooses query keywords.
2. Build trapdoor $(T_1,T_2)$.
3. Server computes search relation with $(I_1,I_2)$ and trapdoor.
4. If relation fails, no result is returned.

### Step E: Partial Decrypt and Final Decrypt
1. Partial decrypt computes pairing-style transformed value $P$ using $C_0$ and $K_{trans}$.
2. Final decrypt reconstructs $s$ from shares and computes user term $D$.
3. Recover $Z'$ by canceling user part from $P$.
4. Derive $K'_{sym} = H_3(C_0\|Z')$.
5. Verify tag $\tau' = H_4(K'_{sym}\|C_{file}\|Z')$.
6. If tag valid, decrypt bytes; otherwise reject.

## 3) Complete Computation Trace (Low-Level, Equation by Equation)

This section follows the same order as the code and shows exact arithmetic logic.
All scalar operations are in $\mathbb{Z}_p$ (implemented as `MOD`), so modulo-$p$ reduction is implicit in all equations below unless explicitly emphasized.

### 3.1 Setup

Let setup nodes be indexed by $i=1,\dots,m$.

1. Each node samples:
  $$
  \gamma_i \leftarrow \mathbb{Z}_p
  $$
2. Aggregate:
  $$
  \gamma = \sum_{i=1}^{m} \gamma_i
  $$

Code mapping:
- `pp["gamma"]` stores $\gamma$.

### 3.2 KeyGen

Given user attribute set $\mathcal{A}_u$:

1. Sample user secret:
  $$
  k \leftarrow \mathbb{Z}_p
  $$
2. Compute:
  $$
  U = g^k, \quad K_{trans}=g^{\gamma+k}
  $$
3. For each attribute $x \in \mathcal{A}_u$:
  - sample $t_x \leftarrow \mathbb{Z}_p$
  - compute $h_x = H_1(x)$
  - set
    $$
    K_x = g^k, \quad L_x = g^{h_x k + t_x}
    $$

Exponent-space form used in this repo:
- $U \mapsto k$
- $K_{trans} \mapsto \gamma+k$
- $K_x \mapsto k$
- $L_x \mapsto h_x k + t_x$

Code mapping:
- `secret_key["k"]`, `secret_key["K_trans"]`, `secret_key["attribute_keys"][x]["K_x"]`, `...["L_x"]`.

### 3.3 Encrypt (Access + Data + Integrity)

Inputs: plaintext bytes $M$, policy size $n$, keyword set $W$, public $\gamma$.

1. Sample randomness:
  $$
  r \leftarrow \mathbb{Z}_p, \quad s:=r
  $$

2. Secret sharing (Shamir/LSSS style):
  - choose threshold $t$ (in code from `choose_threshold`)
  - choose polynomial
    $$
    f(x)=a_0 + a_1x + \cdots + a_{t-1}x^{t-1}, \quad a_0=s
    $$
  - shares:
    $$
    \lambda_i=f(i), \quad i=1,\dots,n
    $$

3. Core ciphertext terms:
  $$
  C_0=g^r
  $$
  $$
  Z=e(g,g)^{\gamma r}
  $$

4. Symmetric protection:
  $$
  K_{sym}=H_3(C_0 \| Z)
  $$
  $$
  C_{file}=M \oplus K_{sym}
  $$

5. FO-style integrity tag:
  $$
		τ = H_4(K_{sym} \| C_{file} \| Z)
  $$

6. Row values for each policy attribute row $i$ with attribute label $x_i$:
  - sample $u_i \leftarrow \mathbb{Z}_p$
  - compute $h_i=H_1(x_i)$
  - set
    $$
    C_{i,1}=\lambda_i-u_i h_i
    $$
    $$
    C_{i,2}=u_i
    $$

Code mapping:
- `ct["C0"]`, `ct["Z"]`, `ct["ciphertext"]`, `ct["tau"]`, `ct["rows"]`, `ct["shares"]`, `ct["threshold"]`.

### 3.4 Index Generation (Searchable Part)

Given encrypted-document keywords $W=\{w_1,\dots,w_q\}$:

1. Aggregate keyword hash:
  $$
  \Phi = \sum_{j=1}^{q} H_2(w_j)
  $$
2. Sample $\beta \leftarrow \mathbb{Z}_p$.
3. Set index values:
  $$
  I_1 = g^{\Phi(1+\beta)}
  $$
  $$
  I_2 = e(g,g)^{\beta}
  $$

Exponent-space form used in code:
$$
I_1 \mapsto \Phi(1+\beta), \quad I_2 \mapsto \beta
$$

Code mapping:
- `index["Phi"]`, `index["beta"]`, `index["I1"]`, `index["I2"]`.

### 3.5 Trapdoor Generation (Query Side)

Given query keywords $W'=\{w'_1,\dots,w'_{q'}\}$:

1. Query aggregate:
  $$
  \Phi' = \sum_j H_2(w'_j)
  $$
2. Sample $\alpha \leftarrow \mathbb{Z}_p$.
3. Build trapdoor:
  $$
  T_1=g^{\alpha}, \quad T_2=\alpha\Phi'
  $$

Exponent-space form:
$$
T_1 \mapsto \alpha, \quad T_2 \mapsto \alpha\Phi'
$$

Code mapping:
- `trapdoor["Phi_prime"]`, `trapdoor["alpha"]`, `trapdoor["T1"]`, `trapdoor["T2"]`.

### 3.6 Search Check (Exact Expansion)

Code computes:
$$
   lhs = T_1 I_1 - I_2 T_2, \quad rhs = T_2
$$
and returns match iff `lhs == rhs`.

Substitute index/trapdoor exponent forms:
$$
   lhs=\alpha\cdot\Phi(1+\beta)-\beta\cdot(\alpha\Phi')
$$

If keyword sets match, then $\Phi'=\Phi$, hence
$$
   lhs=\alpha\Phi + \alpha\Phi\beta - \alpha\Phi\beta = \alpha\Phi
$$
and
$$
   rhs=T_2=\alpha\Phi' = \alpha\Phi
$$
so `lhs == rhs` holds.

If keyword sets do not match, generally $\Phi' \neq \Phi$ and equality fails.

### 3.7 Partial Decrypt

Compute:
$$
P=e(C_0,K_{trans})=e(g^r, g^{\gamma+k})=e(g,g)^{r(\gamma+k)}
$$

Exponent-space implementation:
$$
P \mapsto C_0 \cdot K_{trans} = r(\gamma+k)
$$

Code mapping:
- `partial["P"]`.

### 3.8 Final Decrypt (Full Derivation)

1. Take threshold shares $(x_i,\lambda_i)$ and reconstruct:
  $$
  s = \sum_{i \in S} \lambda_i \cdot \ell_i(0)
  $$
  where
  $$
  \ell_i(0)=\prod_{j\in S,\,j\neq i}\frac{-x_j}{x_i-x_j}
  $$

2. Compute user cancellation term:
  $$
  D=e(g,g)^{ks}
  $$
  Since $s=r$ in this implementation:
  $$
  D=e(g,g)^{kr}
  $$

3. Cancel from partial result:
  $$
  Z' = P / D
  $$
  Expand exponent:
  $$
  P = e(g,g)^{r(\gamma+k)} = e(g,g)^{\gamma r + kr}
  $$
  $$
  Z' = e(g,g)^{\gamma r + kr - kr}=e(g,g)^{\gamma r}
  $$

4. Re-derive key:
  $$
  K'_{sym}=H_3(C_0 \| Z')
  $$

5. Recompute tag:
  $$
		τ' = H_4(K'_{sym} \| C_{file} \| Z')
  $$

6. Accept and decrypt only if:
  $$
		τ' = τ
  $$
  then
  $$
  M = C_{file} \oplus K'_{sym}
  $$
  else return failure.

Code mapping:
- reconstructed secret: `final["reconstructed_s"]`
- cancellation term: `final["D"]`
- recovered pairing term: `final["Z"]`
- tag check: `final["tag_ok"]`
- plaintext: `final["plaintext"]`

### 3.9 Why $s := r$ Is Mandatory Here

If $s \neq r$, then cancellation leaves an extra term:
$$
Z' = e(g,g)^{r(\gamma+k)-ks}=e(g,g)^{\gamma r + k(r-s)}
$$
This is not equal to $e(g,g)^{\gamma r}$ unless $r=s$, so key reconstruction would fail.

## 4) Practical Outcome and What It Means

In practical systems, this flow provides:
- attribute-based access control (only satisfying users can decrypt)
- searchable capability (server returns only matching encrypted data)
- integrity check via FO-style tag verification before plaintext release

In this repository, we enforce operationally:
- keyword mismatch => search fails => decryption aborted
- insufficient attributes => decryption blocked
- valid match + valid attributes => decryption succeeds

# WHAT WE DID HERE IN THE MOCK IMPLEMENTATION

This project uses an exponent-space mock, not real elliptic-curve pairing cryptography.

## 5) Mock Mapping Used in Code

- Represent $g^x$ by exponent scalar $x \bmod p$.
- Represent pairing $e(g^a,g^b)$ by scalar multiplication $ab \bmod p$.
- Keep algebraic structure needed for flow validation and timing comparison.

This keeps equations consistent while making the code lightweight and easy to benchmark.

## 6) Implementation Files and Purpose

- `mock_abe/setup_algo.py`: setup and $\gamma$ aggregation
- `mock_abe/keygen_algo.py`: user key and attribute components
- `mock_abe/encrypt_algo.py`: encryption, shares, FO tag generation
- `mock_abe/index_algo.py`: searchable index creation
- `mock_abe/trapdoor_algo.py`: query trapdoor generation
- `mock_abe/search_algo.py`: search relation check
- `mock_abe/partial_decrypt_algo.py`: partial transform
- `mock_abe/final_decrypt_algo.py`: share reconstruction, tag validation, final decrypt
- `mock_abe/benchmark.py`: timed sweeps and graph generation
- `run.py`: benchmark entrypoint
- `scripts/end_to_end.py`: full file-based flow demo

## 7) All Run Scripts

### 7.1 Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 7.2 Benchmark + Graphs (main)

```bash
python3 run.py --output outputs
```

### 7.3 Benchmark with custom sweep settings

```bash
python3 run.py \
  --attributes-count 8 \
  --keywords-count 6 \
  --message-size 256 \
  --cycles 5 \
  --repeats-per-cycle 20 \
  --work-multiplier 200 \
  --attr-start 2 --attr-stop 10 --attr-step 2 \
  --keyword-start 2 --keyword-stop 10 --keyword-step 2 \
  --text-start 64 --text-stop 320 --text-step 64 \
  --output outputs
```

### 7.4 Single preview run from benchmark parser

```bash
python3 run.py \
  --attributes "attr1,attr2" \
  --keywords "kw1,kw2" \
  --message "preview message" \
  --output outputs
```

### 7.5 End-to-end file flow (match case)

```bash
PYTHONPATH=. python3 scripts/end_to_end.py scripts/sample_input.txt \
  --out test_match \
  --attributes "attr1,attr2" \
  --policy-attributes "attr1,attr2" \
  --encrypt-keywords "kw1,kw2" \
  --query-keywords "kw1,kw2" \
  --seed 12345
```

### 7.6 End-to-end keyword mismatch (expected: no result)

```bash
PYTHONPATH=. python3 scripts/end_to_end.py scripts/sample_input.txt \
  --out test_kw_mismatch \
  --attributes "attr1,attr2" \
  --policy-attributes "attr1,attr2" \
  --encrypt-keywords "kw1,kw2" \
  --query-keywords "kwX" \
  --seed 12345
```

### 7.7 End-to-end attribute mismatch (expected: decrypt blocked)

```bash
PYTHONPATH=. python3 scripts/end_to_end.py scripts/sample_input.txt \
  --out test_attr_mismatch \
  --attributes "attr3" \
  --policy-attributes "attr1,attr2" \
  --encrypt-keywords "kw1,kw2" \
  --query-keywords "kw1,kw2" \
  --seed 12345
```

## 8) Output Artifacts

### Benchmark outputs (default `outputs/`)
- `time_vs_attributes.png`
- `time_vs_keywords.png`
- `encrypted_text_keywords_heatmap.png`
- `index_vs_time.png`
- `trapdoor_vs_time.png`
- `sum_vs_time.png`
- `attributes_benchmark.csv`
- `keywords_benchmark.csv`

### End-to-end outputs (`--out` directory)
- `ct.json` (ciphertext package)
- `index.json` (search index)
- `recovered_<input-file>` (present only when search and decryption succeed)

## 9) Important Note

This is a correctness and benchmarking mock. It is suitable for demonstrating flow, equations, and timing trends, but it is not secure production cryptography.
## Contibuted by Bhavya Sree and Team 
