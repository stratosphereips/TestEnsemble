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


def count_infectedSrcDestFlows_byIPSrc (df):
#This function decide the label for each IPSrc as infected or clean based in the label about his connection to IPDst and (Later) IP Dst information (from VirusTotal, Thread Intelligence and the SrcBehaviour (SLIPS alerts about scanning for example).


   d = {}
   
   for t in df.itertuples():
       if (t.SrcAddr not in d.keys()):
           d[t.SrcAddr] = {'totalInfectedDestinations': 0, 'totalDestinations':0, 'originalLabel':''}
       if (t.FinalLabel=='Infected'):
           d[t.SrcAddr]['totalInfectedDestinations'] += 1
       d[t.SrcAddr]['totalDestinations'] += 1
       d[t.SrcAddr]['originalLabel']=t.srcOriginalLabel
   
              
   return d


def get_labelForIPSrc_basedincount_infectedSrcDstFlows(df,d,count_threshold):
#df is the original dataset
#d is the dictionary created with a counter that repesent the total infected pairs IPSrc-IPDst resulting of phase2 ensembling
#if the totalInfectedDestination counter is great or equal to a threshold parameter --> the IPSrc is labeled as infected
#d2 is the result dictionary

     d2 = {}
     TP = 0
     FP = 0
     TN = 0
     FN = 0
     for src in list(set(df.SrcAddr)):
         d2[src]={'LabelIPSrc':'Clean','originalLabel':''}
         if (d[src]['totalInfectedDestinations']>=count_threshold):
             d2[src]['LabelIPSrc']='Infected'
             #The original label can be added here, I did it below but it is better here to do it more efficient
         d2[src]['originalLabel']=d[src]['originalLabel']
             #here we can obtain TP,TN,FP and FN values
         if (d2[src]['LabelIPSrc']=='Infected'):
             if (d2[src]['originalLabel']=='Infected'):
                 TP +=1
             else:
                 if (d2[src]['originalLabel']=='Clean'):
                     FP +=1
         else:
             if (d2[src]['originalLabel']=='Infected'):
                 FN +=1
             else:
                 if (d2[src]['originalLabel']=='Clean'):
                     TN +=1
                          

     return d2, TP, FP, TN, FN			
def get_labelForIPSrc_basedinpercentege_infectedSrcDstFlows(df,d,percentege_threshold):
#df is the original dataset
#d is the dictionary created with a counter that repesent the total infected pairs IPSrc-IPDst resulting of phase2 ensembling
#if the totalInfectedDestination counter is great or equal to a threshold parameter --> the IPSrc is labeled as infected
#d2 is the result dictionary

     d2 = {}
     TP = 0
     FP = 0
     TN = 0
     FN = 0 

     for src in list(set(df.SrcAddr)):
         d2[src]={'LabelIPSrc':'Clean','originalLabel':''}
         if (((d[src]['totalInfectedDestinations'])/(d[src]['totalDestinations']))>=percentege_threshold):
             d2[src]['LabelIPSrc']='Infected'
             #The original label can be added here, I did it below but it is better here to do it more efficient
         d2[src]['originalLabel']=d[src]['originalLabel']
             #here we can obtain TP,TN,FP and FN values
         if (d2[src]['LabelIPSrc']=='Infected'):
             if (d2[src]['originalLabel']=='Infected'):
                 TP +=1
             else:
                 if (d2[src]['originalLabel']=='Clean'):
                     FP +=1
         else:
             if (d2[src]['originalLabel']=='Infected'):
                 FN +=1
             else:
                 if (d2[src]['originalLabel']=='Clean'):
                     TN +=1
                          

     return d2, TP, FP, TN, FN			

def create_dataset_labelByIPSrc(d2):
						    
    df2 = pd.DataFrame([key for key in d2.keys()], columns=['SrcAddr'])
    df2['LabelIPSrc'] = [value['LabelIPSrc'] for value in d2.values()]
    df2['srcOriginalLabel'] = [value['originalLabel'] for value in d2.values()]
    
    return df2
	
def create_dataset_confusionmatrix(dConfusion):
						    
    df4 = pd.DataFrame([key for key in dConfusion.keys()], columns=['PercentegeCountThresholdPIDst'])
    df4['ThresholdPercentegeMaliciousFlowsPerIPDst'] = [value['ThresholdPercentegeMaliciousFlowsPerIPDst'] for value in dConfusion.values()]
    df4['ThresholdCounterMaliciousFlowsPerIPDst'] = [value['ThresholdCounterMaliciousFlowsPerIPDst'] for value in dConfusion.values()]
    df4['criteriaIPDstEnsembling'] = [value['criteriaIPDstEnsembling'] for value in dConfusion.values()]
    df4['ThresholdMaliciousIPSrc-IPDst'] = [value['ThresholdMaliciousIPSrc-IPDst'] for value in dConfusion.values()]
    df4['FP'] = [value['FP'] for value in dConfusion.values()]
    df4['FN'] = [value['FN'] for value in dConfusion.values()]
    df4['TP'] = [value['TP'] for value in dConfusion.values()]
    df4['TN'] = [value['TN'] for value in dConfusion.values()]
    df4['FalsePositiveRate'] = [value['FalsePositiveRate'] for value in dConfusion.values()]
    df4['TruePositiveRate'] = [value['TruePositiveRate'] for value in dConfusion.values()]
    df4['F1Score'] = [value['F1Score'] for value in dConfusion.values()]
    df4['Accuracy'] = [value['Accuracy'] for value in dConfusion.values()]

    return df4

print('Starting')

dConfusion = {}

#We can do it for all files (dynamic filename and datasetout)
 
counter=0
percentege=0
TCPEP=0
TCPNEP=0
UDPEP=0
UDPNEP=0
os.chdir('resultCounter'+str(counter)+'-Percentege'+str(percentege))
filename = "result"+str(counter)+str(percentege)+".csv"

archivo=open(filename)
df = pd.read_csv(archivo, sep=',')

d = count_infectedSrcDestFlows_byIPSrc (df)

#I use 1 as threshold

count_threshold=1
       
d2, TP, FP, TN, FN = get_labelForIPSrc_basedincount_infectedSrcDstFlows(df,d,count_threshold)

df2 = create_dataset_labelByIPSrc(d2)

export_csv = df2.to_csv ('resultCounter'+str(counter)+'-Percentege'+str(TCPEP)+'CountThreshold'+str(count_threshold), index = None, header=True)


FPR = FP / (FP + TN)
TPR = TP / (TP + FN) 
F1Score = (2*TP) / ((2*TP) + FP + FN)
Accuracy =  (TP + TN) / (TP + FP + TN + FN)

print('FPR')
print(FPR)
print ('TPR')
print(TPR)
print('F1Score')
print(F1Score)
print('Accuracy')
print(Accuracy)


