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



def buildDatasetForEachIP(df,src):
#For each IPSrc, build a dataset with destination IPs + the label
			    
     df2 = df[df["SrcAddr"]==src]
     df2 = df2.drop(['ClaveSrcIPDstIP', 'TCPEstablishedPercentage', 'TCPNotEstablishedPercentage', 'UDPEstablishedPercentage', 'UDPNotEstablishedPercentage', 'cantTCPE', 'cantTCPNE','cantUDPE', 'cantUDPNE', 'totalFlows', 'totalPackets', 'totalBytes', 'TCPELabel', 'TCPNELabel', 'UDPELabel', 'UDPNELabel'], axis=1)

     return df2
	

print('Starting')

#We can do it for all files (dynamic filename and datasetout)
for counter in [0,1,5,10,25,50]:
   TCPEP=0
   TCPNEP=0
   UDPEP=0
   UDPNEP=0
   for percentege in [0,0.25,0.50,0.75,1.0]:
   #Add LOOP to do it for all directories 
       os.chdir('resultCounter'+str(counter)+'-Percentege'+str(percentege))
       filename = "result"+str(counter)+str(percentege)+".csv"
       # for each IPSrc we build a dataset resultante con la etiqueta para todos sus destinos
       archivo=open(filename)
       df = pd.read_csv(archivo, sep=',')
       for src in list(set(df.SrcAddr)):
           #Obtener un dataset para cada IPOrigen con todos sus destinos y sus labels: IMPLEMENTAR!!!
           srcDataset=buildDatasetForEachIP(df,src)
           export_csv = srcDataset.to_csv (str(src)+'LabelsForAllDst.csv', index = None, header=True)
                       
       os.chdir('..')


