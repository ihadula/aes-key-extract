import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv("test_correct.csv", names=['encs', 'percents'])
encs = data['encs'].tolist() 
percents = data['percents'].tolist()

plt.plot(encs, percents, marker='.', linestyle='-', color='grey')

for enc, percent in zip(encs, percents):
    if percent == 100:
        plt.plot(enc, percent, marker='o', color='green', markersize=4)

if 100 in percents:
    index_100 = percents.index(100)
    enc_100 = encs[index_100]
    plt.axvline(x=enc_100, color='green', linestyle='dashed', linewidth=1)
    plt.text(enc_100 + 200, 101, 'Over 750 trials, all 750 extracted keys were correct', verticalalignment='bottom', horizontalalignment='left')

plt.ylim(top=np.max(percents) + 6)
plt.xlabel('Number of encryptions observed')
plt.ylabel('% of keys extracted with 100% accuracy')
plt.xticks(np.arange(3500, 30500, 1000))
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout() 
plt.show()