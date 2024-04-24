import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

data = pd.read_csv("test_accuracy.csv", names=['encs', 'percents'])
encs = data['encs'].tolist() 
percents = data['percents'].tolist()

plt.plot(encs, percents, marker='.', linestyle='-', color='orange')

for enc, percent in zip(encs, percents):
    if percent == 100:
        plt.plot(enc, percent, marker='o', color='green', markersize=4)

if 100 in percents:
    index_100 = percents.index(100)
    enc_100 = encs[index_100]
    plt.axvline(x=enc_100, color='green', linestyle='dashed', linewidth=1)
    plt.text(enc_100, 102, '100% Accuracy over 750 trials', verticalalignment='bottom', horizontalalignment='center')

plt.ylim(top=np.max(percents) + 7)
plt.xlabel('Number of encryptions observed')
plt.ylabel('% correct hex digits extracted from key')
plt.xticks(np.arange(3500, 30500, 1000))
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout() 
plt.show()