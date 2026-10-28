# AICS Technical Viva Voce Defense Dossier
## Course: Artificial Intelligence for Cyber Security (`23AI2001`)
### Academic Evaluation: Parameter 5 (Project Report, PPT and Viva Voce — 10 Marks)

---

## 1. Overview & Viva Strategy

This dossier prepares the candidate to defend **MailForenSIX** before internal and external academic examiners for **Course `23AI2001`**. Questions are divided into 5 technical tiers:
1. **Mathematical Foundations & Loss Functions**
2. **Corpus Engineering & NLP Preprocessing**
3. **Model Evaluation & Empirical Trade-offs**
4. **Explainable AI (LIME) & Feature Ablation**
5. **Cybersecurity Protocol Forensics & Antivirus Limits**

---

## Tier 1: Mathematical Foundations & Algorithmic Loss Functions

### Q1: Why did you train 5 distinct algorithms instead of relying solely on an ensemble like XGBoost?
**Answer:**
Syllabus Module 2 (*"Detecting Spam with SVMs, Naive Bayes, Logistic Regression, Decision Trees"*) explicitly requires understanding how diverse learning paradigms interact with high-dimensional cyber threat data. 
- **Multinomial Naive Bayes** represents a **generative probabilistic model** assuming conditional feature independence.
- **Linear SVM** is a **discriminative maximum-margin hyperplane separator** optimizing geometric separation.
- **Logistic Regression** is a **generalized linear model** directly optimizing calibrated posterior probabilities via cross-entropy.
- **Decision Trees (CART)** provide **non-parametric recursive orthogonal partitioning**.
- **HistGradientBoosting** is an **additive tree ensemble** optimizing residuals in function space.
By training all 5 on identical 31,164 stratified samples, we empirically isolate algorithmic bias, calibration fidelity, and operational latency ($0.2\,\mu\text{s}$ vs. $4.3\,\mu\text{s}$).

---

### Q2: State the exact mathematical loss function minimized by your Logistic Regression model.
**Answer:**
We minimize the multi-class multinomial cross-entropy (log-loss) with $L_2$ Tikhonov regularization:
$$\mathcal{L}(\mathbf{W}) = -\frac{1}{N} \sum_{i=1}^{N} \sum_{c=0}^{2} y_{ic} \ln P(y_i = c \mid \mathbf{x}_i) + \frac{1}{2C} \sum_{c=0}^{2} \|\mathbf{w}_c\|_2^2$$
Where:
- $N$ is the number of training samples ($24,931$).
- $c \in \{0, 1, 2\}$ represents the three classes (`Legitimate`, `Spam`, `Phishing`).
- $y_{ic} \in \{0, 1\}$ is the one-hot encoded ground truth.
- $P(y_i = c \mid \mathbf{x}_i) = \frac{\exp(\mathbf{w}_c^T \mathbf{x}_i + b_c)}{\sum_{k=0}^{2} \exp(\mathbf{w}_k^T \mathbf{x}_i + b_k)}$ is the Softmax function.
- $C = 1.0$ is the inverse regularization strength penalizing extreme parameter weights to avoid overfitting on sparse lexical features.

---

### Q3: What loss function does Linear SVM optimize, and why doesn't standard `LinearSVC` output class probabilities?
**Answer:**
`LinearSVC` minimizes the squared hinge loss with $L_2$ regularization:
$$\min_{\mathbf{w}, b} \frac{1}{2}\|\mathbf{w}\|^2 + C \sum_{i=1}^{n} \max(0, 1 - y_i(\mathbf{w}^T \mathbf{x}_i + b))^2$$
Because SVM optimizes the geometric margin separating hyperplanes, its output is a signed Euclidean distance $f(\mathbf{x}) = \mathbf{w}^T \mathbf{x} + b \in (-\infty, +\infty)$, **not a posterior probability**.
To enable probabilistic risk scoring and multi-class LIME compatibility, we wrap `LinearSVC` in **Platt Sigmoid Calibration** (`CalibratedClassifierCV`):
$$P(y = 1 \mid f(\mathbf{x})) = \frac{1}{1 + \exp(A \cdot f(\mathbf{x}) + B)}$$
Where parameters $A$ and $B$ are fitted via maximum likelihood on a held-out calibration split.

---

### Q4: Why did you use a Linear SVM kernel instead of an RBF (Radial Basis Function) or Polynomial kernel?
**Answer:**
Text classification with TF-IDF yields high-dimensional, highly sparse feature spaces ($D = 10,000$ dimensions).
According to Vapnik's statistical learning theory, when the dimensionality $D$ is very large, the data is almost always linearly separable in the primal feature space without needing an explicit mapping into an infinite-dimensional Hilbert space via the RBF kernel.
Furthermore, training an RBF kernel scales as $\mathcal{O}(N^2)$ to $\mathcal{O}(N^3)$ with respect to sample size $N$, making it computationally prohibitive for real-time gateway mail analysis, whereas Linear SVM solved via coordinate descent (`LIBLINEAR`) trains in $\mathcal{O}(N \cdot \text{nnz})$ time, delivering an inference latency of just $2.1\,\mu\text{s}$.

---

### Q5: Explain the role and formula of Laplace Smoothing in your Multinomial Naive Bayes classifier.
**Answer:**
In standard Maximum Likelihood Estimation for Multinomial Naive Bayes, the likelihood of a term $w_k$ given class $c$ is:
$$\hat{P}(w_k \mid c) = \frac{N_{ck}}{N_c}$$
If an incoming email contains an unobserved word or a zero-frequency token for class $c$, $N_{ck} = 0$. Because Naive Bayes multiplies feature probabilities together:
$$P(c \mid d) \propto P(c) \prod_{k=1}^{V} P(w_k \mid c)^{f_k}$$
A single zero term wipes out the entire joint probability ($P(c \mid d) = 0$).
To prevent this zero-probability pathology, we implement **Laplace (Lidstone) Additive Smoothing** with $\alpha = 0.1$:
$$P(w_k \mid c) = \frac{N_{ck} + \alpha}{N_c + \alpha V}$$
Where $V = 10,000$ is the vocabulary size. This guarantees all lexical tokens maintain a strictly positive probability floor.

---

### Q6: What splitting criterion is used in your Decision Tree, and why did it perform lower than Linear models?
**Answer:**
The Decision Tree classifier uses the **Gini Impurity** criterion:
$$Gini(t) = 1 - \sum_{i=0}^{2} p(i \mid t)^2$$
The tree iteratively selects the feature split that maximizes impurity reduction:
$$\Delta Gini = Gini(parent) - \frac{N_L}{N} Gini(child_L) - \frac{N_R}{N} Gini(child_R)$$
**Why it underperformed (83.59% Acc vs. 93.34% LR):**
Decision trees perform axis-aligned orthogonal partitions parallel to individual feature axes. However, textual email threats are governed by dense linear combinations of many subtle lexical tokens acting in unison. A single tree suffers from high variance and cannot effectively capture global linear combinations across $10,000$ sparse dimensions without fragmenting data at deep leaf nodes.

---

## Tier 2: Corpus Engineering & NLP Tokenization

### Q7: Why did you construct a 3-class corpus rather than sticking to binary Ham vs. Phish?
**Answer:**
Binary classification collapses two fundamentally distinct operational categories into a single class:
1. **Spam (Commercial Bulk):** Marketing, unsolicited discounts, newsletters. The impact is low (inbox clutter, minor bandwidth consumption). The SOC action is simply moving to the junk folder.
2. **Phishing (Credential / BEC Fraud):** Account suspension alerts, fake portal links, executive wire transfer requests. The impact is catastrophic (ransomware deployment, corporate credential harvesting, wire fraud). The SOC action requires immediate firewall blacklisting, credential resets, and SIEM alerting.
Conflating Spam and Phishing blinds the security team to threat severity. Tripartite classification directly addresses Syllabus Module 2 and enables proportional incident triage.

---

### Q8: What synthetic domain tokens did you inject during text preprocessing, and why?
**Answer:**
We injected four domain-specific synthetic tokens:
1. `URL_TOKEN`: Replaces variable HTTP/HTTPS strings, preserving link density without fragmenting vocabulary across random domains.
2. `IP_TOKEN`: Replaces raw IPv4 addresses (`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`) often used in unmapped malicious relay hosts.
3. `CURRENCY_TOKEN`: Captures monetary lure amounts (`$`, `€`, `£`, `INR`, `USD`) characteristic of lottery spam and BEC wire transfer attacks.
4. `URGENCY_TOKEN`: Flags psychological urgency triggers (`immediate action required`, `account suspended`, `verify identity`, `24 hours`).
These synthetic tokens turn volatile lexical variations into invariant semantic markers that regularize linear classifiers.

---

### Q9: Why did you use Sublinear TF scaling in your TF-IDF vectorizer?
**Answer:**
Standard Term Frequency $TF(t, d) = \text{count}(t, d)$ assumes that a word occurring 20 times is 20 times as informative as a word occurring once. In phishing emails, an attacker or legal disclaimer may repeat certain terms multiple times without linearly increasing semantic threat intent.
**Sublinear TF scaling** applies a logarithmic dampening:
$$w_{t, d} = 1 + \log(TF(t, d)) \quad \text{for } TF > 0$$
This preserves term significance while preventing keyword-stuffing attacks from distorting the cosine distance between feature vectors.

---

## Tier 3: Model Evaluation, Bias-Variance Tradeoff & Latency

### Q10: Walk me through the empirical results. Which model won, and why?
**Answer:**
Evaluated on the unseen $20\%$ test set ($6,233$ stratified emails):
- **Logistic Regression (L2):** **93.34% Accuracy**, **0.9334 Macro F1**, **0.2 $\mu\text{s}$ latency**.
- **Linear SVM (Platt):** **93.28% Accuracy**, **0.9328 Macro F1**, **2.1 $\mu\text{s}$ latency**.
- **HistGradientBoosting:** **91.22% Accuracy**, **0.9124 Macro F1**, **4.3 $\mu\text{s}$ latency**.
- **Multinomial Naive Bayes:** **87.58% Accuracy**, **0.8741 Macro F1**, **1.8 $\mu\text{s}$ latency**.
- **Decision Tree:** **83.59% Accuracy**, **0.8361 Macro F1**, **0.5 $\mu\text{s}$ latency**.

**Winner:** Logistic Regression achieved the highest overall Macro F1 score ($0.9334$) and the lowest inference latency ($0.2\,\mu\text{s}$ per email), establishing the Pareto-optimal frontier for real-time gateway filtering.

---

### Q11: Explain the Bias-Variance Tradeoff observed across your 5 models.
**Answer:**
- **High Bias / Low Variance (Multinomial Naive Bayes):** The conditional independence assumption introduces strong inductive bias ($P(w_i, w_j \mid c) = P(w_i \mid c) P(w_j \mid c)$). It resists overfitting on small data but plateaus at $87.58\%$ because it cannot model token correlations.
- **Low Bias / High Variance (Single Decision Tree):** Deep recursive partitioning memorizes training noise, resulting in the lowest generalization accuracy ($83.59\%$).
- **Balanced Regularized Discriminators (Logistic Regression & Linear SVM):** Through $L_2$ weight penalization ($\frac{1}{2C}\|\mathbf{w}\|^2$), these models optimize the structural risk minimization boundary, achieving the highest test set generalization ($>93.3\%$) with minimal variance.

---

### Q12: Why did you evaluate Macro-F1 instead of Micro-F1 or raw Accuracy?
**Answer:**
- **Raw Accuracy** can be misleading in security applications if class distributions shift or if minority attack variants are masked by a large benign baseline.
- **Micro-F1** aggregates global True Positives and False Positives, giving equal weight to each sample, meaning majority classes dominate the score.
- **Macro-F1** computes the harmonic mean of Precision and Recall for each class independently and averages them unweighted:
  $$\text{Macro-F1} = \frac{F1_{\text{Legitimate}} + F1_{\text{Spam}} + F1_{\text{Phishing}}}{3}$$
This treats credential phishing detection as equally critical as legitimate email preservation, penalizing any model that sacrifices phishing detection to artificially boost accuracy.

---

## Tier 4: Explainable AI (LIME) & Feature Ablation

### Q13: What is the mathematical formulation of LIME, and how does it explain black-box predictions?
**Answer:**
LIME (Local Interpretable Model-agnostic Explanations, Ribeiro et al., 2016; Pan & Mishra, 2023) explains an individual prediction by approximating the complex global decision boundary locally with an interpretable surrogate model:
$$\xi(x) = \arg\min_{g \in G} \mathcal{L}(f, g, \pi_x) + \Omega(g)$$
Where:
- $f(x)$ is the original black-box classifier.
- $g \in G$ is a simple surrogate model (e.g., Ridge regression: $g(z') = \mathbf{w}_g^T z'$).
- $\pi_x(z) = \exp(-D(x, z)^2 / \sigma^2)$ is an exponential kernel measuring the proximity (cosine distance) between the perturbed instance $z$ and the original instance $x$.
- $\mathcal{L}$ is the squared loss weighted by proximity $\pi_x(z)$.
- $\Omega(g)$ penalizes surrogate complexity (limiting top feature coefficients to $K = 8$).

---

### Q14: What were the findings of your systematic Feature Ablation experiment?
**Answer:**
We evaluated four incremental feature setups on the identical test split:
1. **Setup 1 (Raw Bag-of-Words):** Accuracy: $91.42\%$, Macro F1: $0.9145$ (Baseline).
2. **Setup 2 (TF-IDF Unigrams):** Accuracy: $92.76\%$, Macro F1: $0.9276$ ($+1.31\%$ gain).
3. **Setup 3 (Sublinear TF-IDF Unigrams + Bigrams):** Accuracy: $93.18\%$, Macro F1: $0.9318$ ($+1.73\%$ gain).
4. **Setup 4 (Hybrid TF-IDF + Dense Structural Metadata via `scipy.sparse.hstack`):** Accuracy: **93.28%**, Macro F1: **0.9327** ($\mathbf{+1.83\%}$ gain).
**Academic Conclusion:** Bigram collocations capture multi-word phishing phrases (`account suspended`, `verify identity`), while dense structural features (URL count, uppercase ratio, urgency tokens) provide an orthogonal signal that yields a total $+1.83\%$ improvement over raw term frequencies.

---

## Tier 5: Cybersecurity Protocol Engines & Threat Limits Analysis

### Q15: How does your Account & Domain Reputation Scoring Engine (ADRSE) calculate its score?
**Answer:**
Implemented in `backend/engines/auth.py`, the ADRSE combines cryptographic protocol states with identifier alignment into a discrete $0 - 100$ point asset protection score:
$$\text{Reputation} = w_{\text{SPF}} \cdot S_{\text{SPF}} + w_{\text{DKIM}} \cdot S_{\text{DKIM}} + w_{\text{DMARC}} \cdot S_{\text{DMARC}} + w_{\text{Align}} \cdot S_{\text{Align}} - \text{SpoofPenalty}$$
- **SPF (Max 25 pts):** Pass = 25, Softfail/Warn = 12, Fail = 0.
- **DKIM (Max 25 pts):** Pass (valid RSA/Ed25519 body/header hash) = 25, Fail = 0.
- **DMARC (Max 30 pts):** Pass (Enforced `reject` or `quarantine` policy) = 30, Warn (`p=none`) = 15, Fail = 0.
- **Identifier Alignment (Max 20 pts):** `Header.From` domain exactly matches envelope `Return-Path` domain = 20, Mismatch = 0.
- **Spoof Penalty:** Active domain impersonation or display-name spoofing deducts $-20$ points.
The score maps to discrete trust grades: **A** ($90–100$), **B** ($75–89$), **C** ($50–74$), **D** ($25–49$), and **F** ($<25$).

---

### Q16: How does Course Outcome 2 (*"Predict the antivirus limits in threat detection"*) apply to your project?
**Answer:**
We conducted an empirical benchmark comparing traditional cryptographic hash-based antivirus signatures (MD5 / SHA-256) against semantic machine learning classifiers on zero-day polymorphic phishing lures (`eval_av_limits.py`):
1. **Cryptographic Avalanche Effect:** When an attacker alters a single word, inserts a tracking parameter (`?ref=9284`), or paraphrases using generative AI, the cryptographic hash changes completely. Traditional signature AV exhibited a **0.0% detection rate** on the 5 polymorphic mutations.
2. **AI Semantic Generalization:** Because our trained TF-IDF vectorizer and classifiers extract invariant latent features and urgency markers, MailForenSIX detected **100.0%** of the zero-day mutations with an average confidence of $>80\%$.

---

### Q17: What is Shannon Entropy, and how does it triage email attachments?
**Answer:**
Shannon Entropy measures the average information density and randomness of byte sequences in bits per byte ($0.0 \le H \le 8.0$):
$$H(X) = -\sum_{i=0}^{255} p(b_i) \log_2 p(b_i)$$
Where $p(b_i)$ is the empirical probability of byte value $b_i$ in the file buffer.
- **Plaintext & Benign Documents (PDF, HTML, Code):** Bytes exhibit predictable statistical redundancy ($H \approx 4.0 - 5.5$ bits/byte).
- **Compiled Executables (PE x86/x64):** Standard machine code and resources exhibit moderate entropy ($H \approx 5.8 - 6.8$ bits/byte).
- **Packed, Obfuscated, or Ransomware Payloads (UPX, AES encrypted):** High randomness produces an almost uniform distribution across all 256 byte values ($H \ge 7.2$ bits/byte).
Our triage engine automatically flags any attachment with $H \ge 7.2$ as high-risk packed malware before dynamic execution.

---

### Q18: What is the difference between SPF, DKIM, and DMARC?
**Answer:**
- **SPF (Sender Policy Framework, RFC 7208):** Authorizes which IP addresses are permitted to send mail on behalf of a domain via DNS TXT records. *Limitation:* It checks only the envelope sender (`MAIL FROM`), not the user-visible `From:` header.
- **DKIM (DomainKeys Identified Mail, RFC 6376):** Uses asymmetric public-key cryptography to digitally sign the email body and critical headers, verifying that the email was not tampered with in transit.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance, RFC 7489):** Bridges the gap by enforcing **Identifier Alignment**—verifying that the domain in the visible `From:` header matches the SPF and DKIM authenticated domains—and tells the receiver what to do if validation fails (`p=none`, `p=quarantine`, `p=reject`).

---

### Q19: Why is the Cost of False Positives higher than False Negatives in enterprise email security?
**Answer:**
- A **False Negative** means a phishing or spam email reaches the inbox. While dangerous, endpoint EDR, browser isolation, and user security awareness training provide secondary defense-in-depth layers.
- A **False Positive** means a legitimate, high-value corporate contract, executive memo, or client invoice is quarantined or discarded. This causes immediate business disruption, contractual breaches, and financial loss.
Therefore, a production mail classifier must achieve near-zero False Positive rates on legitimate corporate mail (achieved by Logistic Regression: $F1_{\text{Legit}} = 0.9458$).

---

### Q20: How does your dynamic API architecture support runtime model switching?
**Answer:**
Implemented in `backend/engines/classifier.py` and `backend/api/routes/analyze.py`:
On startup, the FastAPI application loads all 5 serialized models (`lr.pkl`, `svm.pkl`, `nb.pkl`, `dt.pkl`, `xgb.pkl`) and the pre-fitted AICS vectorizer into an in-memory dictionary `_models_registry`.
Clients pass an optional query parameter:
`POST /api/v1/analyze?model=lr|svm|nb|dt|xgb`
The endpoint dynamically routes the vector through the selected model, computes 3-class probabilities, invokes multi-class LIME attribution for that specific model architecture, and returns the threat tier and ADRSE reputation score.

---

### Q21: What are the CERT-In incident reporting requirements supported by MailForenSIX?
**Answer:**
Under the Indian Computer Emergency Response Team (CERT-In) cybersecurity directions (Section 70B of the Information Technology Act, 2000), organizations must report specified cybersecurity incidents within 6 hours.
MailForenSIX implements an automated compliance engine (`backend/engines/certin.py`) that maps detected email threats to official CERT-In incident categories (e.g., *Phishing / Identity Theft*, *Compromise of Critical Information Infrastructure*), extracts mandatory forensic IoCs (Source IP, sender domain, cryptographic hash, relay timeline), and prepares a report-ready forensic dossier.

---

### Q22: What is the advantage of using sublinear TF-IDF over dense word embeddings (e.g., Word2Vec/BERT) for email gateway classification?
**Answer:**
While transformer embeddings (BERT/DistilBERT) capture deep bidirectional context, they introduce heavy GPU memory overhead ($>400\,\text{MB}$) and multi-millisecond inference latencies ($>50\,\text{ms}$ per email).
Sublinear TF-IDF with $(1, 2)$ n-grams and domain synthetic tokens fits entirely in RAM ($240\,\text{KB}$ model size), executes in **$0.2\,\mu\text{s}$ on standard CPU hardware**, and achieves **$93.34\%$ Macro F1**, making it 250,000 times faster than transformers and directly suitable for high-throughput enterprise gateway deployments.

---

### Q23: How did you ensure data hygiene and avoid data leakage in your 31,164-sample corpus?
**Answer:**
1. **Deduplication:** We computed MD5 hashes of all email bodies to remove identical duplicates across overlapping corpora (reducing 77,437 raw records to 67,348 unique emails).
2. **Stratified Splitting:** Train/test splitting ($80/20$) was performed *stratified by class label* to guarantee uniform representation across all three classes.
3. **No Target Leakage:** Feature fitting (TF-IDF vocabulary extraction, chi2 selection, and feature scalers) was executed **strictly on the training partition**, and then applied to transform the test partition without peeking.

---

### Q24: How does LIME prevent feature attribution explosion on long emails?
**Answer:**
Rather than perturbing every individual word token in a 5,000-word email—which causes exponential sampling complexity—MailForenSIX implements **Sentence-Unit LIME Tokenization**:
1. The body is parsed into clean, semantic sentence segments using boundary regex.
2. LIME treats each whole sentence as a token unit, masking sentences across 180 perturbation samples.
3. Feature weights are normalized relative to the maximum directional impact ($\frac{|w_i|}{\max |w|}$), displaying only the top $K = 8$ driving sentences.

---

### Q25: If you were to extend this academic project to production, what would be the next engineering step?
**Answer:**
1. **Adversarial Hardening:** Incorporate adversarial perturbation training (e.g., character homoglyphs, invisible zero-width spaces, and LLM evasion paraphrasing) to further harden linear decision margins.
2. **Federated Threat Intelligence:** Connect the ADRSE engine to decentralized DNS-over-HTTPS (DoH) threat telemetry to update domain reputation scores dynamically without exposing corporate email queries.
3. **Automated SIEM Playbooks:** Extend the CERT-In incident generator into automated SOAR (Security Orchestration, Automation, and Response) webhooks to isolate compromised mailboxes automatically.

