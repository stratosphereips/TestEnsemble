import pandas as pd                                                                                    
import matplotlib.pyplot as plt                                                                        
import numpy as np
import io
import os                                                                                                 
import itertools                                                                       
import matplotlib.pyplot as py                                       

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis
from sklearn import model_selection
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold

from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.gaussian_process.kernels import RBF
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from sklearn.ensemble import VotingClassifier


def obtainIPsForTrainingAndTesting(df,percentegetrain,infected,clean):
#df is the original dataset
#precentegetrain is the percentege of IPs to include in training dataset
#infected is the hosts list we know (a priori) they are infected when the dataset was created
#clean is the hosts list we know (a priori) they are clean when the dataset was created

   unknownIPs = []
   for src in list(set(df.SrcAddr)):
       if(not(src in infected))&(not(src in clean))&(not(src=='nan')):
           unknownIPs.append(src)
  
   unknowncounter=len(unknownIPs)
   infectedcounter=len(infected)
   cleancounter=len(clean)
   print('counters unknowncounter infected counter clean counter')   
   print(unknowncounter)
   print(infectedcounter)
   print(cleancounter)
   infectedfortrainingcounter=round((percentegetrain*infectedcounter)/100)
   cleanfortrainingcounter=round((percentegetrain*cleancounter)/100)
   unknownfortrainingcounter=round((percentegetrain*unknowncounter)/100)

   #These are intervals to determine when an IP must be sent to a set for testing
   infectedfortestingcounter=round(infectedfortrainingcounter/(infectedcounter-infectedfortrainingcounter))
   cleanfortestingcounter=round(cleanfortrainingcounter/(cleancounter-cleanfortrainingcounter))
   unknownfortestingcounter=round(unknownfortrainingcounter/(unknowncounter-unknownfortrainingcounter))
    
   IPsForTesting = []
   IPsForTraining = []
   
   for i in range(1 , unknowncounter):
       if ((i % unknownfortestingcounter) == 0):
           IPsForTesting.append(unknownIPs[i])
       else:
           IPsForTraining.append(unknownIPs[i])

   for i in range(1 , infectedcounter):
       if ((i % infectedfortestingcounter) == 0):
           IPsForTesting.append(infected[i])
       else:
           IPsForTraining.append(infected[i])

   for i in range(1 , cleancounter):
       if ((i % cleanfortestingcounter) == 0):
           IPsForTesting.append(clean[i])
       else:
           IPsForTraining.append(clean[i])

   return IPsForTraining, IPsForTesting
#  

def armardatasetnuevo(df,IPList):
#df is the original dataset
#IPList is the SrcAdr whose flows must be included in the new dataset

   df = df[~df.SrcAddr.isin(IPList)]
					
   return df
#

print('Basic Processing Mixed Test Dataset. Real mixed on real-time')
#nombrearchivo='prueba'
#Parámetro: nombre de archivo
#interesting_files=['resultsFase1-dataset1-head.csv','resultsFase1-dataset3-head.csv']
#df_list = []
#for filename in sorted(interesting_files):
#    df_list.append(pd.read_csv(filename))
#    df = pd.concat(df_list)

archivo=open('resultsFase1conrandom-dataset1-2-3.csv') 
   
df = pd.read_csv(archivo, sep=',')

#The set of infected and cleaned hosts are the union of sets of infected and cleaned hosts of the three datasets

infectedHosts=['147.32.84.165','147.32.84.191','147.32.84.192','147.32.84.193','147.32.84.204','147.32.84.205','147.32.84.206','147.32.84.207','147.32.84.208','147.32.84.209','192.168.1.121']
cleanHosts=['147.32.84.170','147.32.84.134','147.32.84.164','147.32.87.36','147.32.80.9','147.32.87.11','192.168.1.2']
#criteria is the list with criterions to define if the conection is malicious or not

percentegetrain=80
IPsForTraining,IPsForTesting = obtainIPsForTrainingAndTesting(df,percentegetrain,infectedHosts,cleanHosts)
print('IPsForTraining')
print(IPsForTraining)
print('IPsForTesting')
print(IPsForTesting)
df_training= armardatasetnuevo(df,IPsForTraining)
export_csv = df_training.to_csv ('training.csv', index = None, header=True)
#falta grabar a csv
df_testing= armardatasetnuevo(df,IPsForTesting)
export_csv = df_testing.to_csv ('testing.csv', index = None, header=True)



