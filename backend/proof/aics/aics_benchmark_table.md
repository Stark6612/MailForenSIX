# AICS Model Comparison Benchmark Table
| Algorithm | Syllabus Alignment | Accuracy | Macro Precision | Macro Recall | Macro F1 | F1 (Ham) | F1 (Spam) | F1 (Phish) | Latency (us) | Size (KB) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Multinomial Naive Bayes** | Module 2 | **87.58%** | 0.8753 | 0.8758 | **0.8741** | 0.9464 | 0.8485 | 0.8275 | 0.3 us | 469.5 KB |
| **Linear SVM** | Module 2 | **93.36%** | 0.9336 | 0.9336 | **0.9336** | 0.9747 | 0.9115 | 0.9145 | 2.1 us | 235.1 KB |
| **Logistic Regression (L2)** | Module 2 | **93.34%** | 0.9334 | 0.9334 | **0.9334** | 0.9733 | 0.9132 | 0.9138 | 0.2 us | 235.2 KB |
| **Decision Tree (CART)** | Module 2 | **83.59%** | 0.8484 | 0.8359 | **0.8372** | 0.8816 | 0.8208 | 0.8091 | 1.8 us | 126.7 KB |
| **Gradient Boosted Trees (HistGB)** | Module 2 | **91.22%** | 0.9131 | 0.9122 | **0.9126** | 0.9590 | 0.8882 | 0.8905 | 392.3 us | 3311.9 KB |
