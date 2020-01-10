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
						    
    df3 = pd.DataFrame([key for key in dConfusion.keys()], columns=['PercentegeCountThresholdPIDst'])
    df3['ThresholdPercentegeMaliciousFlowsPerIPDst'] = [value['ThresholdPercentegeMaliciousFlowsPerIPDst'] for value in dConfusion.values()]
    df3['ThresholdCounterMaliciousFlowsPerIPDst'] = [value['ThresholdCounterMaliciousFlowsPerIPDst'] for value in dConfusion.values()]
    df3['ThresholdMaliciousIPSrc-IPDst'] = [value['ThresholdMaliciousIPSrc-IPDst'] for value in dConfusion.values()]
    df3['FP'] = [value['FP'] for value in dConfusion.values()]
    df3['FN'] = [value['FN'] for value in dConfusion.values()]
    df3['TP'] = [value['TP'] for value in dConfusion.values()]
    df3['TN'] = [value['TN'] for value in dConfusion.values()]
    
    return df3

print('Starting')

dConfusion = {}

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
#infectedHosts=set(['147.32.84.165','147.32.84.191','147.32.84.192','147.32.84.193','147.32.84.204','147.32.84.205','147.32.84.206','147.32.84.207','147.32.84.208','147.32.84.209'])
#cleanHosts=set(['147.32.84.170','147.32.84.134','147.32.84.164','147.32.87.36','147.32.80.9','147.32.87.11'])
#criteria is the list with criterions to define if the conection is malicious or not
       archivo=open(filename)
       df = pd.read_csv(archivo, sep=',')

       d = count_infectedSrcDestFlows_byIPSrc (df)

       #I need implement a for loop to test differents thresholds
       
       for count_threshold in [1,5,10,50]:

           d2, TP, FP, TN, FN = get_labelForIPSrc_basedincount_infectedSrcDstFlows(df,d,count_threshold)

           df2 = create_dataset_labelByIPSrc(d2)

           export_csv = df2.to_csv ('resultCounter'+str(counter)+'-Percentege'+str(TCPEP)+'CountThreshold'+str(count_threshold), index = None, header=True)
           #Add a row to the confusion matrix dataset
           dConfusion ['Percentege:'+str(percentege)+'-Counter:'+str(counter)+'ThresholdIPDst:'+str(count_threshold)]={'ThresholdPercentegeMaliciousFlowsPerIPDst': percentege, 'ThresholdCounterMaliciousFlowsPerIPDst': counter, 'ThresholdMaliciousIPSrc-IPDst': count_threshold, 'FP': FP, 'FN': FN, 'TP': TP, 'TN': TN}
                


       for percentege_threshold in [0.1,0.25,0.50,0.75]:
        
           d3, TP, FP, TN, FN = get_labelForIPSrc_basedinpercentege_infectedSrcDstFlows(df,d,percentege_threshold)

           df3 = create_dataset_labelByIPSrc(d3)

           export_csv = df3.to_csv ('resultCounter'+str(counter)+'-Percentege'+str(TCPEP)+'PercentegeThreshold'+str(percentege_threshold), index = None, header=True)

           #Add a row to the confusion matrix dataset
           dConfusion ['Percentege:'+str(percentege)+'-Counter:'+str(counter)+'ThresholdIPDst:'+str(percentege_threshold)]={'ThresholdPercentegeMaliciousFlowsPerIPDst': percentege, 'ThresholdCounterMaliciousFlowsPerIPDst': counter, 'ThresholdMaliciousIPSrc-IPDst': percentege_threshold, 'FP': FP, 'FN': FN, 'TP': TP, 'TN': TN}
           
       os.chdir('..')

df4 = create_dataset_confusionmatrix(dConfusion)     
export_csv = df4.to_csv ('confusionMatrix.csv', index = None, header=True)

