# To see which type of resoucres like GPU have been alloted - for Google Colab
!nvidia-smi 

# To install and import main libraries
!pip install apriori

!pip install apyori

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from apyori import apriori

# To download the dataset from repo
! git clone https://github.com/Bristol-Cyber-Security-Group/packetsniffing.git

# To import and view the dataset in dataframes
store_data = pd.read_csv('csvfrommessageswithoutlocation.csv')

store_data

# To convert dataframe into a list of lists
records = []
for i in range(len(store_data)):
    records.append([str(store_data.values[i,j]) for j in range(0, 6)])

# To apply Apriori Algorithm 
association_rules = apriori(records, min_support=0.0045, min_confidence=0.2, min_lift=3, min_length=2)

# To convert and view the list of rules
association_results = list(association_rules)

# To view the rules with support, confidence and lift
for item in association_results:
  print("Rule: ", list(item[0])) 
  print("Support: " + str(item[1]))
  print("Confidence: " + str(item[2][0][2]))
  print("Lift: " + str(item[2][0][3]))
  print("=====================================")
