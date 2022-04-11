!nvidia-smi

!pip install apriori

!pip install apyori

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from apyori import apriori

! git clone https://github.com/Bristol-Cyber-Security-Group/packetsniffing.git

store_data = pd.read_csv('csvfrommessageswithoutlocation.csv')

store_data

records = []
for i in range(len(store_data)):
    records.append([str(store_data.values[i,j]) for j in range(0, 6)])

association_rules = apriori(records, min_support=0.0045, min_confidence=0.2, min_lift=3, min_length=2)
association_results = list(association_rules)

for item in association_results:
  print("Rule: ", list(item[0])) 
  print("Support: " + str(item[1]))
  print("Confidence: " + str(item[2][0][2]))
  print("Lift: " + str(item[2][0][3]))
  print("=====================================")