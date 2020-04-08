import pandas as pd                                                                                    
import matplotlib.pyplot as plt                                                                        
import numpy as np
import io                                                                                                 
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

dateparse = lambda x: pd.datetime.strptime(x, '%Y/%m/%d %H:%M:%S.%f') # 2018/07/22 13:01:34.892833

#Procesamiento básico del archivo
def process_file (filename):

   archivo=open(filename) 
   
   dataset = pd.read_csv(archivo, sep=',', parse_dates=['StartTime'] , date_parser=dateparse)

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

    # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   #dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*To-Background-CVUT-Proxy.*$)', 'malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Background.*$)', 'Unknow')

   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-WebServer.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-DNS-Server.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*MatLab-Server*$)', 'Normal')

   # There is still one more label without normal, malware or backround. (an error), so delete it.
   #dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Unknow'
   #The definitive ensembling will not receive labeled flows as Unknoe
   dataset = dataset[~dataset.Label.str.contains("Unknow")]
   
   dataset = dataset.drop('CCDetector(Normal:CC:Unknown)', axis=1)  

   return dataset
##
def process_file_2 (filename):

   archivo=open(filename) 
   
   dataset = pd.read_csv(archivo, sep=',', parse_dates=['StartTime'] , date_parser=dateparse)

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

    # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   #dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*To-Background-CVUT-Proxy.*$)', 'malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Background.*$)', 'Unknow')

   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-WebServer.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-DNS-Server.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*MatLab-Server*$)', 'Normal')

   # There is still one more label without normal, malware or backround. (an error), so delete it.
   #dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Unknow'
   #The definitive ensembling will not receive labeled flows as Unknoe
   dataset = dataset[~dataset.Label.str.contains("Unknow")]
   
   #dataset = dataset.drop('CCDetector(Normal:CC:Unknown)', axis=1)  

   return dataset

#Procesamiento básico del archivo
def process_file_3 (filename):

   archivo=open(filename) 
   
   dataset = pd.read_csv(archivo, sep=',')

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

   # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   #dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*To-Background-CVUT-Proxy.*$)', 'malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Background.*$)', 'Unknow')

   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-WebServer.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-DNS-Server.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*MatLab-Server*$)', 'Normal')

   # There is still one more label without normal, malware or backround. (an error), so delete it.
   #dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Unknow'
   #The definitive ensembling will not receive labeled flows as Unknoe
   dataset = dataset[~dataset.Label.str.contains("Unknow")]
   
   #dataset = dataset.drop('CCDetector(Normal:CC:Unknown)', axis=1)  

   return dataset
##


# This function is used to convert string features into categories for pandas
# A categorical variable takes on a limited, and usually fixed, number of possible values
# In this way, the algorihtms can do something with the features. If not, they can not use them
def make_categorical(dataset, cat):
    '''
    Convert one column to a categorical type
    '''
    # Converts the column to cotegorical
    dataset[cat] = pd.Categorical(dataset[cat])
    # Convert the categories to int. Use this with caution!! we don't want an algorithm 
    # to learn that an Orange=1 is less than a pearl=2
    dataset[cat] = dataset[cat].cat.codes
    return dataset

# This function discards some features and convert others.
# In here you can later modify how you use the features in the flows
# Maybe you want to delete some features, or convert others.
# For example our port feature is not a number now (because of the ICMP codes), but you can change that

# Por ahi no es una mala idea más allá de descartar la IP conservar la información de la red..

def process_features(dataset):
    '''
      # Create categorical features
    '''
    try:
      print('\tMake categorical column {}'.format('StartTime'))
      dataset = make_categorical(dataset, 'StartTime')
    except ValueError:
      pass
#    dataset.reset_index()
#    try:
#     print('\tMake categorical column {}'.format('SrcAddr'))
#      dataset = make_categorical(dataset, 'SrcAddr')
#    except ValueError:
#      pass
#    try:
#      print('\tMake categorical column {}'.format('DstAddr'))
#      dataset = make_categorical(dataset, 'DstAddr')
#    except ValueError:
#      pass
    try:
      print('\tMake categorical column {}'.format('sTos'))
      dataset = make_categorical(dataset, 'sTos')
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('dTos'))
      dataset = dataset.drop('dTos', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('Dir'))
      dataset = dataset.drop('Dir', axis=1)
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('Proto'))
      dataset = make_categorical(dataset, 'Proto')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Sport'))
      dataset = make_categorical(dataset, 'Sport')
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('State'))
      dataset = make_categorical(dataset, 'State')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Dport'))
      dataset = make_categorical(dataset, 'Dport')
    except ValueError:
      pass
    return dataset

def makecategorical_features(dataset):
   # Create categorical features
    try:
      print('\tMake categorical column {}'.format('Dir'))
      dataset = make_categorical(dataset, 'Dir')
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('Proto'))
      dataset = make_categorical(dataset, 'Proto')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Sport'))
      dataset = make_categorical(dataset, 'Sport')
    except ValueError:
      pass
    try:
      print('\tMake categorical column {}'.format('State'))
      dataset = make_categorical(dataset, 'State')
    except ValueError:
      pass
    try:
      # Convert the ports to categorical codes because some ports are not numbers. For exmaple, ICMP has ports with 0x03
      print('\tMake categorical column {}'.format('Dport'))
      dataset = make_categorical(dataset, 'Dport')
    except ValueError:
      pass
    return dataset


def process_dataset_to_countersbyType (df):
#Arma un diccionario en función del dataset recibido
#Procesamiento básico del archivo

   d = {}
 
   for t in df.itertuples():
       if t.SrcAddr not in d.keys():
           d[t.SrcAddr] = {'total1': 0, 'normal': 0, 'malware': 0 }
       if t.DstAddr not in d[t.SrcAddr].keys():
           d[t.SrcAddr][t.DstAddr] = {'total2': 0, 'normal': 0, 'malware': 0 }
       d[t.SrcAddr]['total1'] += 1
       d[t.SrcAddr][t.DstAddr]['total2'] += 1
       if t.Label == 'Normal':
           d[t.SrcAddr]['normal'] += 1
           d[t.SrcAddr][t.DstAddr]['normal'] += 1
       else:
           d[t.SrcAddr]['malware'] += 1
           d[t.SrcAddr][t.DstAddr]['malware'] += 1

   return d

def analyse_flows_infected_hosts(df,infected,clean,d):
#df is the original dataset
#infected is the hosts list we know (a priori) they are infected when the dataset was created
#clean is the hosts list we know (a priori) they are clean when the dataset was created
#d is the dictionary created with different counters

   countinfectedwithmalwareflows=0
   countinfectedwithnormalflows=0
   countinfectedwithbothflows=0
   countcleanwithmalwareflows=0
   countcleanwithnormalflows=0
   countcleanwithbothflows=0
   countunknowwithmalwareflows=0
   countunknowwithnormalflows=0
   countunknowwithbothflows=0
   countinfected=0
   countclean=0
   countunknow=0

   for src in list(set(df.SrcAddr)):
       if(src in infected):
           countinfected+= 1
           if (d[src]['normal']>0)&(d[src]['malware']>0):
               countinfectedwithbothflows+= 1
           else:
               if (d[src]['normal']>0)&(d[src]['malware']==0):
                   countinfectedwithnormalflows+= 1
               else:    
                   if (d[src]['malware']>0)&(d[src]['normal']==0):
                       countinfectedwithmalwareflows+= 1
       else:
           if(src in clean):
               countclean+= 1
               if (d[src]['normal']>0)&(d[src]['malware']>0):
                   countcleanwithbothflows+= 1
               else:
                   if (d[src]['normal']>0)&(d[src]['malware']==0):
                       countcleanwithnormalflows+= 1
                   else:    
                       if (d[src]['malware']>0):
                           countcleanwithmalwareflows+= 1
           else:
               countunknow+= 1
               if (d[src]['normal']>0)&(d[src]['malware']>0):
                   countunknowwithbothflows+= 1
               else:
                   if (d[src]['normal']>0)&(d[src]['malware']==0):
                       countunknowwithnormalflows+= 1
                   else:    
                       if (d[src]['malware']>0)&(d[src]['normal']==0):
                           countunknowwithmalwareflows+= 1

   return countinfectedwithmalwareflows, countinfectedwithnormalflows, countinfectedwithbothflows, countcleanwithmalwareflows, countcleanwithnormalflows, countcleanwithbothflows, countunknowwithmalwareflows, countunknowwithnormalflows, countunknowwithbothflows, countinfected, countclean, countunknow 							


print('Analisis dataset1')
#nombrearchivo='prueba'
#Parámetro: nombre de archivo
nombrearchivo='dataset1-capture20110818-binetflow.csv'
infectedHosts=set(['147.32.84.165','147.32.84.191','147.32.84.192','147.32.84.193','147.32.84.204','147.32.84.205','147.32.84.206','147.32.84.207','147.32.84.208','147.32.84.209'])
cleanHosts=set(['147.32.84.170','147.32.84.134','147.32.84.164','147.32.87.36','147.32.80.9','147.32.87.11'])
d_countersbytype={}

df= process_file(nombrearchivo)
d_countersbytype=process_dataset_to_countersbyType (df)
countinfectedwithmalwareflows, countinfectedwithnormalflows, countinfectedwithbothflows, countcleanwithmalwareflows, countcleanwithnormalflows, countcleanwithbothflows, countunknowwithmalwareflows, countunknowwithnormalflows, countunknowwithbothflows, countinfected, countclean, countunknow=analyse_flows_infected_hosts(df,infectedHosts,cleanHosts,d_countersbytype)

print("countinfected: "+str(countinfected))
print("countinfectedwithmalwareflows: "+str(countinfectedwithmalwareflows))
print("countinfectedwithnormalflows: "+str(countinfectedwithnormalflows))
print("countinfectedwithbothflows: "+str(countinfectedwithbothflows))

print("countclean: "+str(countclean))
print("countcleanwithmalwareflows: "+str(countcleanwithmalwareflows))
print("countcleanwithnormalflows: "+str(countcleanwithnormalflows))
print("countcleanwithbothflows: "+str(countcleanwithbothflows))

print("countunknow"+str(countunknow))
print("countunknowwithmalwareflows: "+str(countunknowwithmalwareflows))
print("countunknowwithnormalflows: "+str(countunknowwithnormalflows))
print("countunknowwithbothflows: "+str(countunknowwithbothflows))

print('Analisis dataset2')
nombrearchivo='dataset2-capture20110819.binetflow'
infectedHosts=set(['147.32.84.165','147.32.84.191','147.32.84.192'])
cleanHosts=set(['147.32.84.170','147.32.84.134','147.32.84.164','147.32.87.36','147.32.80.9','147.32.87.11'])
d_countersbytype={}

df= process_file_2(nombrearchivo)
d_countersbytype=process_dataset_to_countersbyType (df)
countinfectedwithmalwareflows, countinfectedwithnormalflows, countinfectedwithbothflows, countcleanwithmalwareflows, countcleanwithnormalflows, countcleanwithbothflows, countunknowwithmalwareflows, countunknowwithnormalflows, countunknowwithbothflows, countinfected, countclean, countunknow=analyse_flows_infected_hosts(df,infectedHosts,cleanHosts,d_countersbytype)

print("countinfected: "+str(countinfected))
print("countinfectedwithmalwareflows: "+str(countinfectedwithmalwareflows))
print("countinfectedwithnormalflows: "+str(countinfectedwithnormalflows))
print("countinfectedwithbothflows: "+str(countinfectedwithbothflows))

print("countclean: "+str(countclean))
print("countcleanwithmalwareflows: "+str(countcleanwithmalwareflows))
print("countcleanwithnormalflows: "+str(countcleanwithnormalflows))
print("countcleanwithbothflows: "+str(countcleanwithbothflows))

print("countunknow"+str(countunknow))
print("countunknowwithmalwareflows: "+str(countunknowwithmalwareflows))
print("countunknowwithnormalflows: "+str(countunknowwithnormalflows))
print("countunknowwithbothflows: "+str(countunknowwithbothflows))




print('Analisis dataset3')
nombrearchivo='dataset3-2018-05-03_win11.binetflow'
infectedHosts=set(['192.168.1.121'])
cleanHosts=set(['192.168.1.2'])
d_countersbytype={}

df= process_file_3(nombrearchivo)
d_countersbytype=process_dataset_to_countersbyType (df)
countinfectedwithmalwareflows, countinfectedwithnormalflows, countinfectedwithbothflows, countcleanwithmalwareflows, countcleanwithnormalflows, countcleanwithbothflows, countunknowwithmalwareflows, countunknowwithnormalflows, countunknowwithbothflows, countinfected, countclean, countunknow=analyse_flows_infected_hosts(df,infectedHosts,cleanHosts,d_countersbytype)

print("countinfected: "+str(countinfected))
print("countinfectedwithmalwareflows: "+str(countinfectedwithmalwareflows))
print("countinfectedwithnormalflows: "+str(countinfectedwithnormalflows))
print("countinfectedwithbothflows: "+str(countinfectedwithbothflows))

print("countclean: "+str(countclean))
print("countcleanwithmalwareflows: "+str(countcleanwithmalwareflows))
print("countcleanwithnormalflows: "+str(countcleanwithnormalflows))
print("countcleanwithbothflows: "+str(countcleanwithbothflows))

print("countunknow"+str(countunknow))
print("countunknowwithmalwareflows: "+str(countunknowwithmalwareflows))
print("countunknowwithnormalflows: "+str(countunknowwithnormalflows))
print("countunknowwithbothflows: "+str(countunknowwithbothflows))






