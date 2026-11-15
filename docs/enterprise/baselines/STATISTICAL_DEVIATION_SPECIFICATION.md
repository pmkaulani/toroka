# Statistical Deviation Specification

## 1. Why Banking Data Breaks Gaussian Assumptions

Traditional fraud detection engines frequently rely on simple Gaussian statistics (sample mean $\mu$ and standard deviation $\sigma$) to compute $Z$-scores:
$$Z = \frac{x - \mu}{\sigma}$$

In banking operations, this approach fails predictably due to:
1. **End-of-Month Outliers**: Bulk payroll postings or quarterly settlement batches produce extreme values that inflate standard deviation by orders of magnitude.
2. **Masking Effect**: A single large historical spike inflates $\sigma$, causing subsequent anomalous transactions to appear within $3\sigma$ of the mean.
3. **Swamping Effect**: A single outlier pulls $\mu$ toward itself, making normal values appear falsely anomalous.

---

## 2. Robust Statistics: Median Absolute Deviation (MAD)

Toroka Enterprise replaces brittle mean/variance calculations with **Median Absolute Deviation (MAD)** as formulated by Boris Iglewicz and David Hoaglin (1993).

### Step 1: Baseline Median Calculation
For a baseline series $X = \{x_1, x_2, \dots, x_n\}$:
$$\tilde{x} = \text{median}(X)$$

### Step 2: Absolute Deviations
Compute absolute deviations of all historical samples from the baseline median:
$$D_i = |x_i - \tilde{x}| \quad \forall i \in \{1, \dots, n\}$$

### Step 3: Median Absolute Deviation
$$\text{MAD} = \text{median}(D_1, D_2, \dots, D_n)$$

### Step 4: Modified Z-Score
For an observed value $x$:
$$M_i = \frac{0.6745 \cdot (x - \tilde{x})}{\text{MAD}}$$

The constant $0.6745$ scales MAD so that for a normal distribution, $\text{MAD} \approx 0.6745 \cdot \sigma$, making the modified $Z$-score comparable to traditional standard scores without being vulnerable to outliers.

---

## 3. Boundary Conditions & Zero Variance

When historical observations are identical (e.g. an automated process that always generates exactly 10 postings per day), $\text{MAD} = 0$:
- When $\text{MAD} = 0$:
  - If $x = \tilde{x}$, $\text{deviation} = 0.0$ and $\text{is\_anomalous} = \text{False}$.
  - If $x \neq \tilde{x}$, the modified $Z$-score cannot be computed by division; the engine flags the observation as deterministic deviation with $\text{deviation} = 10.0$ and $\text{is\_anomalous} = \text{True}$.

---

## 4. Anomaly Thresholds

An observation is flagged as anomalous if:
$$|M_i| \ge 3.5$$
Recommended by NIST and Iglewicz-Hoaglin as a conservative threshold for outlier identification in empirical data.
