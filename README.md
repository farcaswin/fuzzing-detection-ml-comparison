# Network Fuzzing Attack Detection (UNSW-NB15)

## 1. Project Overview
This project focuses on the development and comparative analysis of Machine Learning models for detecting **Fuzzing** network attacks. By utilizing the UNSW-NB15 dataset, the study evaluates four different algorithms—Logistic Regression, Decision Tree, Random Forest, and XGBoost—to identify the most effective solution for cybersecurity monitoring.

## 2. Experimental Setup

### 2.1 Dataset: UNSW-NB15 (Public)
*   **Source:** [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
*   **Data Type:** Real network traffic records.
*   **Description:** The dataset was generated in the Cyber Range labs of UNSW Canberra, containing a total of 2,540,044 records.
*   **Preprocessing Steps:**
    *   Concatenation of training and testing CSV files to eliminate potential distribution bias.
    *   Removal of irrelevant identifiers (`id`) and multi-class attack labels, focusing on binary classification (Normal vs. Fuzzers).
    *   Imputation of missing or infinite values using median and zero-fill strategies.
    *   Categorical encoding for `proto`, `service`, and `state` features using `LabelEncoder`.
    *   Feature scaling via `StandardScaler` to normalize value intervals across features.

### 2.2 Evaluation Metrics
Model performance was quantified using the following metrics:
*   **Accuracy:** Percentage of correct predictions relative to total cases. $Acc = \frac{TP + TN}{TP + TN + FP + FN}$
*   **Recall:** The ability to correctly identify all real fuzzing attacks (critical for security). $Rec = \frac{TP}{TP + FN}$
*   **Precision:** Percentage of real attacks out of all samples marked as attacks. $Prec = \frac{TP}{TP + FP}$
*   **F1-Score:** Harmonic mean of Precision and Recall, providing a balanced performance measure. $F1 = 2 \cdot \frac{Prec \cdot Rec}{Prec + Rec}$
*   **ROC-AUC:** Measure of the model's ability to distinguish between classes across different probability thresholds.

## 3. Training Methodology

*   **Data Splitting:** A 80% training and 20% testing stratified split was used to maintain class distribution in both subsets.
*   **Balancing:** Due to the dominance of normal traffic, the **SMOTE** (Synthetic Minority Over-sampling Technique) algorithm was applied to the training set to generate synthetic Fuzzer packets.
*   **Model Architectures:**
    *   **Logistic Regression:** Configured with `max_iter=1000` for weight vector convergence. It serves as a linear baseline for class separability.
    *   **Decision Tree:** Limited to `max_depth=10` to prevent overfitting on network noise.
    *   **Random Forest:** An ensemble of `n_estimators=100` trees using bagging. It reduces variance and increases robustness against anomalies.
    *   **XGBoost:** Gradient Boosting optimized with `logloss`, efficient in capturing complex non-linear relationships.

## 4. Results and Analysis

The comparative analysis revealed the following results on the test set:

| Model | Accuracy | Recall | Precision | F1-Score | ROC-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Logistic Regression | 0.8006 | **0.9707** | 0.5094 | 0.6682 | 0.9276 |
| Decision Tree | 0.8541 | 0.8904 | 0.5990 | 0.7162 | 0.9380 |
| Random Forest | **0.9003** | 0.8271 | **0.7279** | **0.7743** | **0.9595** |
| XGBoost | 0.8897 | 0.8383 | 0.6928 | 0.7586 | 0.9574 |

### Analysis
The results highlight a clear contrast between the tested models. **Logistic Regression** dominates in terms of **Recall (97.07%)**, demonstrating an exceptional ability to detect nearly all attacks, albeit at the cost of low **Precision (50.94%)**. This "paranoia" is explained by the decision boundary being pushed in favor of the minority class after SMOTE, which in a real-world SOC environment would generate a high volume of false alarms.

In contrast, **Random Forest** offers the best operational balance, achieving the highest **Accuracy (0.90)** and **F1-Score (0.77)**. Its ability to create complex non-linear boundaries allows for superior precision by isolating normal traffic that simulates Fuzzer behavior. Finally, ROC-AUC values above 0.92 for all algorithms confirm that the intrinsic capacity to distinguish between legitimate and malicious packets remains excellent across all architectures.

## 5. Deployment and UI
A minimalist Streamlit-based interface is included for real-time analysis.
1.  **Installation:** `pip install -r requirements.txt`
2.  **Training:** Run `src/Network_Analyzer.ipynb` to generate models in the `models/` directory.
3.  **Launch UI:** `streamlit run src/app.py`
4.  **Testing:** Upload CSV files from the `test_data/` directory to view classification results and confidence levels.
