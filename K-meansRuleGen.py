# -*- coding: utf-8 -*-
"""
Created on Tue May 31 10:07:03 2022

@author: Luke St John
"""

import csv

import matplotlib.pyplot as plt
from kneed import KneeLocator
from sklearn.datasets import make_blobs
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, adjusted_rand_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

import pandas as pd
import seaborn as sns
import numpy as np
import random
import socket
import binascii

def ClusterIndicesNumpy(clustNum, labels_array): #numpy 
    return np.where(labels_array == clustNum)[0]

dataset1 = pd.read_csv('FinalMLDatasetEdit.csv')

datafile = 'FinalMLDatasetEdit.csv'

data = np.genfromtxt(
    datafile,
    delimiter=",",
    usecols=np.arange(6,40),
    skip_header=1
)

true_label_names = np.genfromtxt(
    datafile,
    delimiter=",",
    usecols=(2),
    skip_header=1
)

data = np.nan_to_num(data)
print(np.any(np.isnan(data)))

print(np.all(np.isfinite(data)))
#print(dataset1)

scaler = StandardScaler()
scaled_features = scaler.fit_transform(data)


kmeans_kwargs = {
    "init": "random",
    "n_init": 10,
    "max_iter": 300,
    "random_state": 42,
}



# A list holds the SSE values for each k
# =============================================================================
# sse = []
# for k in range(1, 50):
#     kmeans = KMeans(n_clusters=k, **kmeans_kwargs)
#     kmeans.fit(scaled_features)
#     sse.append(kmeans.inertia_)
# 
# plt.style.use("fivethirtyeight")
# plt.plot(range(1, 50), sse)
# plt.xticks(np.arange(1, 50, 5))
# plt.xlabel("Number of Clusters")
# plt.ylabel("SSE")
# plt.show()
# 
# kl = KneeLocator(
#     range(1, 50), sse, curve="convex", direction="decreasing"
# )
# 
# print(kl.elbow)
# 
# =============================================================================

# A list holds the silhouette coefficients for each k
silhouette_coefficients = []

# Notice you start at 2 clusters for silhouette coefficient

# =============================================================================
# for k in range(2, 25):
#     kmeans = KMeans(n_clusters=k, **kmeans_kwargs)
#     kmeans.fit(scaled_features)
#     score = silhouette_score(scaled_features, kmeans.labels_)
#     silhouette_coefficients.append(score)
#     
# plt.style.use("fivethirtyeight")
# plt.plot(range(2, 25), silhouette_coefficients)
# plt.xticks(range(2, 25))
# plt.xlabel("Number of Clusters")
# plt.ylabel("Silhouette Coefficient")
# plt.show()
# =============================================================================


n_clusters = 15

print(true_label_names[:5])

label_encoder = LabelEncoder()

true_labels = label_encoder.fit_transform(true_label_names)

print(true_labels[:5])

preprocessor = Pipeline(
    [
        ("scaler", MinMaxScaler()),
        ("pca", PCA(n_components=2, random_state=42)),
    ]
)

clusterer = Pipeline(
   [
       (
           "kmeans",
           KMeans(
               n_clusters=n_clusters,
               init="k-means++",
               n_init=50,
               max_iter=500,
               random_state=42,
           ),
       ),
   ]
)

pipe = Pipeline(
    [
        ("preprocessor", preprocessor),
        ("clusterer", clusterer)
    ]
)

pipe.fit(data)

preprocessed_data = pipe["preprocessor"].transform(data)

print(preprocessed_data)

predicted_labels = pipe["clusterer"]["kmeans"].labels_

print(predicted_labels)

print(silhouette_score(preprocessed_data, predicted_labels))

print(adjusted_rand_score(true_labels, predicted_labels))

pcadf = pd.DataFrame(
    pipe["preprocessor"].transform(data),
    columns=["component_1", "component_2"],
)


pcadf["predicted_cluster"] = pipe["clusterer"]["kmeans"].labels_
pcadf["true_label"] = label_encoder.inverse_transform(true_labels)

#print(pcadf[pcadf.predicted_cluster == 28])
clusterList = []
for i in range(n_clusters):
    clusterList.append(ClusterIndicesNumpy(i, pcadf))


plt.style.use("fivethirtyeight")
plt.figure(figsize=(8, 8))

scat = sns.scatterplot(
    "component_1",
    "component_2",
    s=50,
    data=pcadf,
    hue="predicted_cluster",
    style="true_label",
    palette="Set2",
)

scat.set_title(
    "Clustering of network traffic for malicous threats"
)
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.0)

plt.show()


datafile2= 'FinalMLDatasetEdit.csv'

data3 = np.genfromtxt(
    datafile2,
    delimiter=",",
    usecols=np.arange(4,10),
    skip_header=1,
    dtype="str"
)

data4 = np.genfromtxt(
    datafile2,
    delimiter=",",
    usecols=(0,2),
    skip_header=1,
    dtype="int"
)



print(data4)

l = 0
for i in data4:
    
    if data4[l][1] != 0:
        print(data4[l][1])
        print(l)
        malstart = l
        print(malstart)
        break
    l += 1


extract = []
extract2 = set()
    
maltotal = 0
num = 0;
for cluster in clusterList:
    maltotal = 0;
    for point in cluster:
        if point >= malstart:
            maltotal += 1
    if maltotal/len(cluster) >= 0.99:
        #print(maltotal/len(cluster))
        print("cluster", num, "is a malware cluster")
        

        
        
        x=0
        for i in data4:
            
            if x in clusterList[num]:
                extract2.add(data3[x][0])
            
            x+=1
            
        
            
    print(maltotal/len(cluster))
                

    num+=1;
        

print(len(extract2))


print(len(extract2))

#randval = random.randint(0,3000)
f = open("rulesfile3.pair", "w")
f.write(str(len(extract2)))
f.write('\n')

num4 = 1

for i in extract2:
    #print(i)
    #randval = random.randint(0,3000)
    #f.write(str(randval))
    f.write(str(num4))
    f.write('\n')
    f.write('1')
    f.write('\n')
    f.write('-1')
    f.write('\n')
    f.write('-1')
    f.write('\n')
    f.write('0')
    f.write('\n')
    f.write('1')
    f.write('\n')
    
    ruleip = i
    ruleip = ruleip.split('.')
    ruleip = ' '.join((hex(int(i))[2:] for i in ruleip))
    ruleip = "|" + ruleip + "|"
    #print(ruleip)
    f.write(ruleip)
    
    #raw = socket.inet_aton(i)
    #raw2 = binascii.hexlify(raw)
    #print(raw)
    #f.write(raw)
    f.write('\n')
    
    num4 += 1

f.close()



