import pandas as pd
import math

df = pd.read_csv("dataset_raw.csv")

WINDOW = 5

windows=[]

def entropy(values):
    p = values.value_counts(normalize=True)
    return -(p * p.apply(lambda x: math.log2(x) if x>0 else 0)).sum()

for i in range(0,len(df),WINDOW):

    chunk=df.iloc[i:i+WINDOW]

    if chunk.empty:
        continue

    packets=len(chunk)
    unique=chunk["src"].nunique()
    ent=entropy(chunk["src"])

    label=chunk["label"].max()

    windows.append({
        "packets":packets,
        "unique":unique,
        "entropy":ent,
        "label":label
    })

w=pd.DataFrame(windows)

w["packets_ratio"]=w["packets"]/w["packets"].shift(1).fillna(1)
w["entropy_delta"]=w["entropy"]-w["entropy"].shift(1).fillna(0)
w["unique_ratio"]=w["unique"]/(w["packets"]+1)
w["pps"]=w["packets"]/WINDOW
w["burst_index"]=w["pps"]/w["pps"].rolling(3).mean().fillna(1)

w["packets_ma"]=w["packets"].rolling(5).mean().fillna(w["packets"])
w["entropy_ma"]=w["entropy"].rolling(5).mean().fillna(w["entropy"])

w.to_csv("features_v2.csv",index=False)

print("Features ready")
