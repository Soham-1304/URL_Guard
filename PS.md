# Case Study 149: Malicious URL Classification

## 1. Title
**Malicious URL Classification Using Machine Learning**

---

## 2. Problem Statement
Users frequently access URLs through search engines, emails, advertisements, and social media. Malicious URLs may redirect users to phishing, malware, or fraudulent websites. The objective is to classify URLs as **Benign** or **Malicious** using only the URL string before visiting the site.

---

## 3. Objectives
- Analyze URL characteristics.
- Extract numerical and lexical URL features.
- Build classification models.
- Compare model performance.
- Develop a real-time malicious URL classification prototype.

---

## 4. Machine Learning Algorithms
1. **Logistic Regression**
2. **Naive Bayes**
3. **K-Nearest Neighbors (KNN)**
4. **Decision Tree**
5. **Random Forest**
6. **Gradient Boosting**

---

## 5. Comparative Study
Evaluate and compare all 6 models on:
- **Accuracy**
- **Precision**
- **Recall**
- **F1-score**
- **Confusion Matrix**

*(B.Tech CSE 2024-28 Machine Learning Case Study / Semester V)*

---

## 6. Deployment
Develop a **Streamlit** interface where a user enters a URL.  
**Output:**
- `Benign` / `Malicious` verdict
- Probability score & confidence breakdown
- Key contributing feature flags

---

## 7. Final Analysis & Key Characteristics to Study
Analyze the following features and their distributions across classes:
- **URL length**
- **Number of special characters**
- **Number of subdomains**
- **Presence of suspicious patterns** (keywords, IP host, entropy, risky TLDs, typosquatting)
- **Important features** (via tree-based and permutation importance)
- **Best-performing algorithm**

---

## 8. Research Questions to Be Answered Using ML
1. **Can malicious URLs be classified without visiting the website?**  
   *(Evaluated using URL-only lexical/structural features on grouped test & fresh URL datasets)*
2. **Which URL features are most predictive?**  
   *(Feature importance ranking via Random Forest / Gradient Boosting & ablation)*
3. **Which algorithm performs best?**  
   *(Head-to-head comparison across all 6 models on identical domain-grouped splits)*
4. **Does URL length contribute to classification?**  
   *(Length distribution analysis by class + ablation with vs without length features)*
5. **How does feature engineering improve results?**  
   *(Baseline raw/simple lexical features vs full engineered feature set)*
6. **Can the system classify previously unseen URLs?**  
   *(Evaluated on domain-grouped held-out test and the live URLhaus fresh feed)*
