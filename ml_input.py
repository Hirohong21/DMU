# Models
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC

# Measuring Accuracy
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, plot_roc_curve 

# Data processing
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler
import joblib

# Save and load models
import pickle

# Managing Datasets
import pandas as pd
# Maths
import numpy as np

def format_columns(df):
    with open('ml_data/columns_used.txt') as f:
        lines = f.read().splitlines()
    existing_columns = lines
    for col in existing_columns:
        if col not in df.columns:
            df[col] = 0
    for col in df.columns:
        if col not in existing_columns:
            df = df.drop(col, axis=1)
    return df

def execute(url):
    url = format_columns(url)

    rfc = pickle.load(open('ml_models/rfc', 'rb'))
    lr = pickle.load(open('ml_models/lr', 'rb'))
    knn = pickle.load(open('ml_models/knn', 'rb'))
    svc = pickle.load(open('ml_models/svc', 'rb'))

    ml_data = url

    scaler = joblib.load('std_scaler.bin')
    x = scaler.transform(ml_data)

    results = []
    for m in [rfc, lr, knn, svc]:
        pred = m.predict(x)
        results.append(pred[0])

    return results

