# MailForenSIX: AI-Driven Multi-Class Email Threat Detection, Explainable Artificial Intelligence (XAI), and Protocol Authentication Platform
## Comprehensive Academic Project Report — Course: 23AI2001 (AICS)

### Evaluation Rubric Compliance (40 Marks Total)
- **1. Technical Proficiency & Implementation (10M):** Multi-model pipeline, dynamic REST API, 3-class feature tokenization.
- **2. Problem-Solving Ability (5M):** Resolving the Spam vs. Phishing boundary; Antivirus signature limits demonstration.
- **3. Use of AI Models & Techniques (5M):** Naive Bayes, Linear SVM, Logistic Regression, Decision Trees, Gradient Boosted Trees, and LIME.
- **4. Project Output & Result Analysis (5M):** Multi-model comparison matrix, per-class F1, confusion matrices, latency benchmark.
- **5. Project Report, PPT and Viva Voce (10M):** Full academic report, loss function derivations, and viva defense guide.
- **6. Online Certification (5M):** Industry cybersecurity credential mapping.

### Multi-Model Empirical Benchmark Results (Unseen Stratified Test Set: 6,233 samples)
| Model | Syllabus Alignment | Accuracy | Macro F1 | F1 (Ham) | F1 (Spam) | F1 (Phish) | Latency | Model Size |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Linear SVM** | Module 2 (SVMs) | **93.36%** | **0.9336** | 0.9747 | 0.9115 | 0.9145 | 2.1 µs | 235.1 KB |
| **Logistic Regression (L2)** | Module 2 (Logistics) | **93.34%** | **0.9334** | 0.9733 | 0.9132 | 0.9138 | 0.2 µs | 235.2 KB |
| **HistGradientBoosting** | Module 2 (Ensembles) | **91.22%** | **0.9126** | 0.9548 | 0.8915 | 0.8875 | 392.3 µs | 3.3 MB |
| **Multinomial Naive Bayes** | Module 2 (Naive Bayes) | **87.58%** | **0.8741** | 0.9464 | 0.8485 | 0.8275 | 0.3 µs | 469.5 KB |
| **Decision Tree (CART)** | Module 2 (Decision Trees) | **83.59%** | **0.8372** | 0.9012 | 0.8045 | 0.8060 | 1.8 µs | 126.7 KB |

*(See full HTML / PDF report for detailed chapters, mathematical derivations, LIME explainability analysis, and ADRSE account reputation engine)*.
