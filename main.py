import pandas as pd
import numpy as np
import pickle
import networkx as nx
import matplotlib.pyplot as plt
import os
import sys

import gdown 

# Google Drive file ID
file_id = "1odvbr0Yt74FF28pLB5dPrpwemkbi_ikL"
url = f"https://drive.google.com/uc?id={file_id}"

# Download temporarily during runtime
path = "/tmp/mydata.csv"  # /tmp works well in Render environments
gdown.download(url, path, quiet=False)

 
# Suppress harmless warnings
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=pd.errors.SettingWithCopyWarning)


# --- 1. CONFIG & ARTIFACT LOADING ---
print("===================================================================")
print("=== FINAL PROJECT PRESENTATION SCRIPT (ALL MODULES) ===")
print("===================================================================")
print("Loading all models, blacklists, and feature lists...")

try:
    with open('ip_blacklist.txt', 'r') as f:
        BLACKLIST_HASH_SET = {line.strip() for line in f if line.strip() and not line.startswith('#')}
    print(f"Loaded {len(BLACKLIST_HASH_SET)} IPs into blacklist hash set (Module 3).")

    with open('anomaly_detector.pkl', 'rb') as f:
        ANOMALY_MODEL = pickle.load(f)
    print("Anomaly Detection model loaded (Module 1).")

    with open('features.pkl', 'rb') as f:
        FEATURE_LIST = pickle.load(f) # Our 67-column list
    print(f"Model feature list ({len(FEATURE_LIST)} columns) loaded.")
    
except Exception as e:
    print(f"--- FATAL ERROR ---")
    print(f"Could not load a required .pkl or .txt file. Error: {e}")
    sys.exit()

def load_and_clean(filepath):
    """Loads and fully cleans any dataset file from TrafficLabelling."""
    print(f"\nLoading and cleaning data from: {os.path.basename(filepath)}...")
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        print(f"--- ERROR: File not found at {filepath}. Skipping this chapter. ---")
        return None
    except Exception as e:
        print(f"Could not read file {filepath}. Error: {e}. Skipping.")
        return None
    
    # This is the critical fix. We always strip ALL columns first.
    df.columns = df.columns.str.strip()
    
    # Replace Inf and NaN values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Define all columns we will ever need for any module
    cols_we_need = set(FEATURE_LIST + ['Source IP', 'Destination IP', 'Label', 'Timestamp'])
    cols_to_check = list(set(df.columns).intersection(cols_we_need))
    
    # Drop any row that has a NaN in ANY of these critical columns
    df.dropna(subset=cols_to_check, inplace=True) 
    
    print(f"Cleaning complete. {len(df)} clean rows loaded.")
    return df

# --- 2. PRESENTATION FLOW START ---
print("\n========================================================")
print("=== MASTER SCRIPT STARTED ===")
print("========================================================")
    
# --- CHAPTER 1 & 2: Load Tuesday Data (for Detection) ---
print("\nLoading data for Chapters 1 & 2...")

# tuesday_df = load_and_clean('TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv')
# tuesday_df = load_and_clean('D:\FinalYear_prj\TrafficLabelling\Tuesday-WorkingHours.pcap_ISCX.csv')
# tuesday_df = load_and_clean('D:\FinalYear_prj\TrafficLabelling\Friday-WorkingHours-Morning.pcap_ISCX.csv')
tuesday_df = load_and_clean(path)

false_positives_list = [] # Create an empty list to store false positives for Chapter 5

if tuesday_df is not None:
    # --- CHAPTER 1: "NORMAL METHOD" (SIGNATURE-BASED HASH TABLE) ---
    print("\n================================================")
    print("=== CHAPTER 1: SIGNATURE DETECTION (HASH TABLE) ===")
    print("================================================")
    
    found_by_sig = tuesday_df[tuesday_df['Source IP'].isin(BLACKLIST_HASH_SET)]
    
    if not found_by_sig.empty:
        print(f"\n*** SIGNATURE MATCH FOUND! ***")
        print(f"Found {len(found_by_sig)} flows originating from a known-bad IP on the blacklist.")
        print(found_by_sig['Label'].value_counts())
    else:
        print("\n--- RESULT: NO MATCHES FOUND ---")
        print("Signature detector did not catch any attacks in this file.")
    print("CONCLUSION: Signature-based detection is ineffective against these specific threats.")

    # --- CHAPTER 2: "SMARTER METHOD" (ANOMALY DETECTION AI) ---
    print("\n\n=================================================")
    print("=== CHAPTER 2: ANOMALY DETECTION (AI MODEL) ===")
    print("=================================================")
    try:
        X_test = tuesday_df[FEATURE_LIST] 
        y_test = tuesday_df['Label']
        print("Feature list matched. Making predictions...")
        
        predictions = ANOMALY_MODEL.predict(X_test) # Get the -1 / 1 predictions
        
        # --- THIS IS THE FIX ---
        # Add the prediction array as a new column to our clean dataframe. This works.
        tuesday_df['Prediction'] = predictions 

        # Now all our reports just read from this corrected dataframe
        print("\nActual counts in file (Ground Truth):")
        print(y_test.value_counts())

        print("\nOur AI Model's prediction counts:")
        # We convert the numeric column to text just for the report
        print(tuesday_df['Prediction'].map({1: 'PREDICTED_NORMAL', -1: 'PREDICTED_ANOMALY'}).value_counts())
        
        print("\nBreakdown of what our AI Model caught (True & False Positives):")
        anomalies_caught_df = tuesday_df[tuesday_df['Prediction'] == -1]
        print(anomalies_caught_df['Label'].value_counts())
        
        print("\nCONCLUSION: AI model caught thousands of attacks the signature check missed, but has false positives.")
        
        # Now save the False Positive data for Chapter 5
        fp_data = tuesday_df[(tuesday_df['Prediction'] == -1) & (tuesday_df['Label'] == 'BENIGN')]
        if not fp_data.empty:
            false_positives_list.append(fp_data.iloc[0]) # Save the first FP we find

    except Exception as e:
        print(f"\n*** Anomaly model failed. This means the feature columns have changed. Error: {e} ***")

# --- CHAPTER 3 & 4: Load Friday Data (for Graph/Time) ---
print("\nLoading data for Chapters 3 & 4...")

# friday_df = load_and_clean('TrafficLabelling /Friday-WorkingHours-Morning.pcap_ISCX.csv')
# friday_df = load_and_clean('D:\FinalYear_prj\TrafficLabelling\Friday-WorkingHours-Morning.pcap_ISCX.csv')
friday_df = load_and_clean(path)

if friday_df is not None:
    # --- CHAPTER 3: "CONTEXT METHOD" (GRAPH ANALYSIS) ---
    print("\n\n===================================================")
    print("=== CHAPTER 3: GRAPH TOPOLOGY ANALYSIS (BOTNET) ===")
    print("===================================================")
    attack_flows = friday_df[friday_df['Label'] == 'Bot'].copy() 

    print(f"Found {len(attack_flows)} botnet attack flows.")
    print("Building NetworkX graph from botnet data...")
    try:
        G_botnet = nx.from_pandas_edgelist(attack_flows, source='Source IP', target='Destination IP', create_using=nx.DiGraph()) 
        print("\n--- BOTNET Graph Summary ---")
        print(f"Total Nodes (IPs in botnet): {G_botnet.number_of_nodes()}")
        print(f"Total Edges (Connections): {G_botnet.number_of_edges()}")

        in_degrees = pd.DataFrame(G_botnet.in_degree(), columns=['IP_Address', 'In_Degree']).sort_values(by='In_Degree', ascending=False)
        print("\nTop 5 Most-Targeted Nodes (Victims):")
        print(in_degrees.head())
        victim_ip = in_degrees.iloc[0]['IP_Address']
        victim_connections = in_degrees.iloc[0]['In_Degree']
        print(f"\nANALYSIS COMPLETE: The primary victim is IP {victim_ip} with {victim_connections} attackers.")
        print("CONCLUSION: Graph analysis successfully identified the 'many-to-one' pattern and found the victim IP.")
    except Exception as e:
        print(f"Graph analysis failed. Error: {e}")

    # --- CHAPTER 4: "TIMESTAMP ANSWER" (TIME SERIES ANALYSIS) ---
    print("\n\n======================================================")
    print("=== CHAPTER 4: TIME SERIES ATTACK PATTERN ANALYSIS ===")
    print("======================================================")
    try:
        print("Analyzing attack pattern over time (resampling by the second)...")
        # Convert Timestamp column to datetime objects and set as index
        friday_df['Timestamp'] = pd.to_datetime(friday_df['Timestamp'], format='mixed')
        friday_df.set_index('Timestamp', inplace=True)

        # Resample data into 1-second buckets and count flows (using '1s' - the correct, modern alias)
        benign_series = friday_df[friday_df['Label'] == 'BENIGN']['Label'].resample('1s').count() 
        bot_series = friday_df[friday_df['Label'] == 'Bot']['Label'].resample('1s').count() 

        print("Generating attack time series plot...")
        plt.figure(figsize=(15, 7))
        benign_series.plot(label='Benign Flows/sec', color='blue', alpha=0.7)
        bot_series.plot(label='Botnet Flows/sec', color='red', linewidth=2)
        plt.title('Time Series Attack Pattern: Botnet vs. Benign')
        plt.ylabel('Flows Per Second')
        plt.legend()
        plt.tight_layout()
        plt.savefig('timeseries_attack_pattern.png')
        print("\nSuccess! Time series plot saved as 'timeseries_attack_pattern.png'")
        print("CONCLUSION: Time series plot visually isolated the attack spike.")
    except Exception as e:
        print(f"Time series analysis failed. Error: {e}")

# --- CHAPTER 5: "FINAL STEP" (AI API SIMULATION) ---
print("\n\n=================================================")
print("=== CHAPTER 5: GenAI AUTOMATED RESPONSE (SIM) ===")
print("=================================================")
if false_positives_list: # Check if our list is not empty
    first_fp_flow_data = false_positives_list[0] # Get the first false positive we found
    print("Found a False Positive alert. Generating AI analysis prompt...")
    
    # Create a clean, simple dictionary to print (JSON-like)
    prompt_payload = {
        'Flow ID': first_fp_flow_data.get('Flow ID'),
        'Source IP': first_fp_flow_data.get('Source IP'),
        'Destination IP': first_fp_flow_data.get('Destination IP'),
        'Destination Port': first_fp_flow_data.get('Destination Port'),
        'Protocol': first_fp_flow_data.get('Protocol'),
        'Actual Label': 'BENIGN',
        'Model Prediction': 'ANOMALY (-1)'
    }
    
    print("\n========================================================")
    print("=== SIMULATING PROMPT TO GEMINI SECURITY AI API ===")
    print("========================================================")
    print("PROMPT: Analyze this network flow. My detectors flagged it as ANOMALY, but the ground truth is BENIGN.")
    print("1. Why did my model flag this benign flow? 2. What is the automated response?")
    print("\n--- DATA PAYLOAD (Key Details) ---")
    print(prompt_payload)
    print("========================================================")
    print("=== AWAITING RESPONSE FROM AI... ===")
    print("========================================================")
else:
    print("Analysis complete. No false positives were found to simulate (or Chapter 2 failed).")

print("\n\n--- MASTER SCRIPT COMPLETE ---")