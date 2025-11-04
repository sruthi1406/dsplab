import streamlit as st
import pandas as pd
import numpy as np
import io

# -------------------------------------------------------
# Built-in Sample Datasets (for easy demonstration)
# -------------------------------------------------------
SAMPLE_DATASETS = {
    "No PII Dataset (Products)": pd.DataFrame({
        "Product": ["Laptop", "Chair", "Pen", "Notebook", "Table"],
        "Price": [55000, 2500, 10, 50, 3000],
        "Category": ["Electronics", "Furniture", "Stationery", "Stationery", "Furniture"]
    }),

    "PII Dataset (People)": pd.DataFrame({
        "Name": ["John Doe", "Amit Patel", "Ravi Kumar", "Sara Khan", "Priya Sharma"],
        "Age": [25, 32, 29, 40, 35],
        "Gender": ["M", "M", "M", "F", "F"],
        "Zip": [56001, 56002, 56003, 56004, 56005],
        "Diagnosis": ["Flu", "Healthy", "COVID", "Diabetes", "Flu"]
    })
}

# -------------------------------------------------------
# Utility Functions
# -------------------------------------------------------
def generalize_zip(zipcode, level):
    if pd.isna(zipcode): return zipcode
    s = str(zipcode)
    if level <= 0: return s
    if level >= len(s): return "*" * len(s)
    return s[:len(s) - level] + "*" * level

def generalize_age(age, bin_size):
    if pd.isna(age): return age
    try:
        age = int(age)
    except ValueError:
        return age
    start = (age // bin_size) * bin_size
    return f"{start}-{start+bin_size-1}"

def equivalence_classes(df, quasi_identifiers):
    if not quasi_identifiers:
        grouped = pd.DataFrame(columns=quasi_identifiers + ["count"])
        merged = df.copy()
        merged["count"] = len(df)
        return merged, grouped
    grouped = df.groupby(quasi_identifiers).size().reset_index(name="count")
    merged = df.merge(grouped, on=quasi_identifiers, how="left")
    return merged, grouped

def reidentification_risk(df, quasi_identifiers):
    if not quasi_identifiers:
        n = len(df)
        if n == 0:
            return {"min_eq_size": 0, "avg_eq_size": 0, "naive_min_risk": 1.0, "unique_fraction": 0.0}
        return {"min_eq_size": n, "avg_eq_size": float(n), "naive_min_risk": 1.0 / n, "unique_fraction": 0.0}

    _, grouped = equivalence_classes(df, quasi_identifiers)
    if grouped.empty and len(df) > 0:
        n = len(df)
        return {"min_eq_size": n, "avg_eq_size": float(n), "naive_min_risk": 1.0 / n, "unique_fraction": 0.0}
    elif grouped.empty and len(df) == 0:
        return {"min_eq_size": 0, "avg_eq_size": 0, "naive_min_risk": 1.0, "unique_fraction": 0.0}
    min_size = int(grouped["count"].min())
    avg_size = float(grouped["count"].mean())
    naive_min_risk = 1.0 / min_size if min_size > 0 else 1.0
    unique_frac = (grouped["count"] == 1).sum() / len(df)
    return {"min_eq_size": min_size, "avg_eq_size": avg_size, "naive_min_risk": naive_min_risk, "unique_fraction": unique_frac}

def apply_k_anonymity(df, quasi_identifiers, k):
    df_work = df.copy()

    def make_qis(d, zip_level, age_bin):
        d = d.copy()
        qi_cols_used = []
        if "Zip" in quasi_identifiers and "Zip" in d.columns:
            d["Zip_g"] = d["Zip"].apply(lambda z: generalize_zip(z, zip_level))
            qi_cols_used.append("Zip_g")
        if "Age" in quasi_identifiers and "Age" in d.columns:
            d["Age_g"] = d["Age"].apply(lambda a: generalize_age(a, age_bin))
            qi_cols_used.append("Age_g")
        for q in quasi_identifiers:
            if q not in ["Zip", "Age"] and q in d.columns:
                qi_cols_used.append(q)
        return d, list(set(qi_cols_used))

    zip_level = 0
    age_bin = 5
    zipped, risk_qis = make_qis(df_work, zip_level, age_bin)
    if not risk_qis:
        stats = reidentification_risk(df_work, [])
        return df_work, stats, []

    stats = reidentification_risk(zipped, risk_qis)
    max_zip_level, max_age_bin = 5, 80

    while stats["min_eq_size"] < k:
        if "Zip" in quasi_identifiers and zip_level < max_zip_level:
            zip_level += 1
        elif "Age" in quasi_identifiers and age_bin < max_age_bin:
            age_bin = min(age_bin * 2, max_age_bin)
        else:
            break
        zipped, risk_qis = make_qis(df_work, zip_level, age_bin)
        stats = reidentification_risk(zipped, risk_qis)

    return zipped, stats, risk_qis

def l_diversity_check(df, quasi_identifiers, sensitive_attr, l):
    if sensitive_attr not in df.columns:
        return {"total_classes": 0, "failing_classes": 0, "failing_fraction": 0.0, "error": f"Sensitive attribute '{sensitive_attr}' not found."}
    if not quasi_identifiers:
        distinct_sens = df[sensitive_attr].nunique()
        failing = 1 if distinct_sens < l else 0
        return {"total_classes": 1, "failing_classes": failing, "failing_fraction": float(failing)}
    merged = df.groupby(quasi_identifiers)[sensitive_attr].nunique().reset_index(name="distinct_sens")
    failing = merged[merged["distinct_sens"] < l]
    return {"total_classes": len(merged), "failing_classes": len(failing), "failing_fraction": (len(failing) / len(merged)) if len(merged) > 0 else 0}

def t_closeness_check(df, quasi_identifiers, sensitive_attr, t):
    if sensitive_attr not in df.columns:
        return {"num_classes": 0, "failing_classes": 0, "failing_fraction": 0.0, "error": f"Sensitive attribute '{sensitive_attr}' not found."}
    if not quasi_identifiers:
        return {"num_classes": 1, "failing_classes": 0, "failing_fraction": 0.0}
    global_dist = df[sensitive_attr].value_counts(normalize=True)
    grouped = df.groupby(quasi_identifiers)
    failing, num_classes = 0, 0
    for _, group in grouped:
        num_classes += 1
        class_dist = group[sensitive_attr].value_counts(normalize=True)
        all_idx = global_dist.index.union(class_dist.index)
        gd, cd = global_dist.reindex(all_idx, fill_value=0), class_dist.reindex(all_idx, fill_value=0)
        tvd = 0.5 * (gd - cd).abs().sum()
        if tvd > t:
            failing += 1
    return {"num_classes": num_classes, "failing_classes": failing, "failing_fraction": failing / num_classes if num_classes > 0 else 0}

def apply_differential_privacy(df, numeric_cols, epsilon):
    df2 = df.copy()
    scale = 1.0 / epsilon
    for col in numeric_cols:
        if col in df2.columns:
            noise = np.random.laplace(0, scale, size=len(df2))
            df2[col + "_dp"] = (df2[col] + noise).round().astype(int)
    return df2


# -------------------------------------------------------
# Streamlit UI
# -------------------------------------------------------
st.set_page_config(page_title="PII Anonymizer with Demo", layout="wide")
st.title("🔐 PII Anonymizer — Interactive Privacy Demo")

st.write("You can **upload your own CSV** or use one of the built-in sample datasets below to test anonymization and risk evaluation.")

# Sample dataset selection
choice = st.selectbox("📦 Choose Dataset:", ["Upload my own file"] + list(SAMPLE_DATASETS.keys()))

if choice == "Upload my own file":
    uploaded_file = st.file_uploader("Upload CSV dataset", type=["csv"])
    if uploaded_file:
        df_raw = pd.read_csv(uploaded_file)
        st.success("✅ File uploaded successfully.")
    else:
        st.info("Upload a file to continue.")
        st.stop()
else:
    df_raw = SAMPLE_DATASETS[choice]
    st.info(f"Loaded **{choice}** successfully.")

st.subheader("📄 Dataset Preview")
st.dataframe(df_raw.head(10))

# Sidebar Settings
st.sidebar.header("⚙️ Privacy Settings")

available_cols = df_raw.columns.tolist()
df_anon = df_raw.copy()

if 'Name' in available_cols:
    df_anon = df_anon.drop(columns=['Name'])
    available_cols.remove('Name')
    st.sidebar.caption("✅ 'Name' column (Direct PII) dropped automatically.")

default_qi = [c for c in ["Age", "Gender", "Zip"] if c in available_cols]
quasi_identifiers = st.sidebar.multiselect("Select Quasi-Identifiers (QIs)", available_cols, default=default_qi)

sensitive_attr = st.sidebar.selectbox("Select Sensitive Attribute", available_cols, index=len(available_cols)-1)
numeric_cols = [c for c in available_cols if pd.api.types.is_numeric_dtype(df_anon[c])]
epsilon = st.sidebar.slider("ε (Differential Privacy)", 0.1, 5.0, 1.0, step=0.1)
k = st.sidebar.slider("k (k-Anonymity)", 2, 10, 3)
l = st.sidebar.slider("l (l-Diversity)", 1, 5, 2)
t = st.sidebar.slider("t (t-Closeness)", 0.0, 1.0, 0.25, step=0.05)

# -------------------------------------------------------
# Apply Anonymization
# -------------------------------------------------------
if st.button("🔒 Apply Anonymization"):
    with st.spinner("Applying anonymization techniques..."):
        risk_before = reidentification_risk(df_anon, quasi_identifiers)
        an_k, stats_k, qi_cols_anonymized = apply_k_anonymity(df_anon, quasi_identifiers, k)
        l_stats = l_diversity_check(an_k, qi_cols_anonymized, sensitive_attr, l)
        t_stats = t_closeness_check(an_k, qi_cols_anonymized, sensitive_attr, t)
        an_dp = apply_differential_privacy(an_k, numeric_cols, epsilon)
        risk_after = reidentification_risk(an_dp, qi_cols_anonymized)

    st.success("✅ Anonymization Completed Successfully")

    col1, col2 = st.columns(2)
    with col1:
        st.write("### Before Anonymization")
        st.json(risk_before)
    with col2:
        st.write("### After Anonymization")
        st.json(risk_after)

    st.write("---")
    st.write(f"**k-Anonymity Stats:** {stats_k}")
    st.write(f"**l-Diversity Stats:** {l_stats}")
    st.write(f"**t-Closeness Stats:** {t_stats}")

    st.subheader("🔍 Anonymized Dataset (Top 10 Rows)")
    st.dataframe(an_dp.head(10))

    csv = an_dp.to_csv(index=False).encode('utf-8')
    st.download_button("📥 Download Anonymized CSV", csv, "anonymized_dataset.csv", "text/csv")

st.markdown("---")
st.caption("Educational Streamlit demo for privacy-preserving data publishing.")
