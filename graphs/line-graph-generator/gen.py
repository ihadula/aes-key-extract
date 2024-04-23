import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv("test_runs.csv", names=['encs', 'percents'])
encs = data['encs'].tolist() 
percents = data['percents'].tolist()

plt.plot(encs, percents, marker='.', linestyle='-', color='red')

plt.xlabel('Number of encryptions observed')
plt.ylabel('% correct bits in extracted key')
plt.xticks(np.arange(4000, 17500, 500))
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout() 
plt.show()