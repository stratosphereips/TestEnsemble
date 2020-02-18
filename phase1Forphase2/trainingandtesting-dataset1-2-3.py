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
from sklearn.externals import joblib 

dateparse = lambda x: pd.datetime.strptime(x, '%Y/%m/%d %H:%M:%S.%f') # 2018/07/22 13:01:34.892833


def process_file1 (filename):

   archivo=open(filename) 
   
   dataset = pd.read_csv(archivo, sep=',', parse_dates=['StartTime'] , date_parser=dateparse)

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

   # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')

   # There is still one more label without normal, malware or backround. (an error), so delete it.
   dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Background'
   dataset = dataset[~dataset.Label.str.contains("Background")]

   dataset = dataset.drop('CCDetector(Normal:CC:Unknown)', axis=1)  

   return dataset
##


def process_file2 (filename):

   archivo=open(filename) 
   
   #dataset = pd.read_csv(archivo, sep=',', parse_dates=['StartTime'] , date_parser=dateparse)
   dataset = pd.read_csv(archivo, sep=',')

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

   # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   #dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Malicious.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   #dataset.Label = dataset.Label.str.replace(r'(^.*To-Background-CVUT-Proxy.*$)', 'Malware')
   
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-WebServer.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-DNS-Server.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*MatLab-Server*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*To-DHCP-server*$)', 'Normal')

   dataset.Label = dataset.Label.str.replace(r'(^.*Background.*$)', 'Unknow')
   
   # There is still one more label without normal, malware or backround. (an error), so delete it.
   #dataset = dataset[~dataset.Label.str.contains("Established")]
   # Also delete all the rows that are labeled 'Unknow'
   #The definitive ensembling will not receive labeled flows as Unknoe
   dataset = dataset[~dataset.Label.str.contains("Unknow")]
   
   #dataset = dataset.drop('CCDetector(Normal:CC:Unknown)', axis=1)  

   return dataset
##

def process_file3 (filename):

   archivo=open(filename) 
   
   #dataset = pd.read_csv(archivo, sep=',', parse_dates=['StartTime'] , date_parser=dateparse)
   dataset = pd.read_csv(archivo, sep=',')

   # Clean the normal dataset by deleting the rows without Label (now only the management records from Argus)
   dataset = dataset.dropna(subset=['Label'], how='any', axis=0)

   # Replace the column Label for only 'Malware', 'Normal' or 'Background'
   #dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*Botnet.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Malicious.*$)', 'Malware')
   dataset.Label = dataset.Label.str.replace(r'(^.*Normal.*$)', 'Normal')
   #dataset.Label = dataset.Label.str.replace(r'(^.*To-Background-CVUT-Proxy.*$)', 'Malware')
   
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-WebServer.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*CVUT-DNS-Server.*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*MatLab-Server*$)', 'Normal')
   dataset.Label = dataset.Label.str.replace(r'(^.*To-DHCP-server*$)', 'Normal')

   dataset.Label = dataset.Label.str.replace(r'(^.*Background.*$)', 'Unknow')
   
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
    Discards some features of the dataset and can create new.
    '''
    try:
      print('\tDiscarding column {}'.format('StartTime'))
      dataset = dataset.drop('StartTime', axis=1)
    except ValueError:
      pass
    dataset.reset_index()
    try:
      print('\tDiscarding column {}'.format('SrcAddr'))
      dataset = dataset.drop('SrcAddr', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('DstAddr'))
      dataset = dataset.drop('DstAddr', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('sTos'))
      dataset = dataset.drop('sTos', axis=1)
    except ValueError:
      pass
    try:
      print('\tDiscarding column {}'.format('dTos'))
      dataset = dataset.drop('dTos', axis=1)
    except ValueError:
      pass
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

print('Basic Processing Mixed Test Dataset. Real mixed on real-time')
interesting_files=['dataset1-capture20110818-binetflow.csv','dataset2-capture20110819.binetflow','dataset3-2018-05-03_win11.binetflow']

nombredataset1 = 'dataset1-capture20110818-binetflow.csv'
nombredataset2 = 'dataset2-capture20110819.binetflow'
nombredataset3 = 'dataset3-2018-05-03_win11.binetflow' 

df1 = process_file1(nombredataset1)
df2 = process_file2(nombredataset2)
df3 = process_file3(nombredataset3)

df_original = [df1,df2,df3]
df_list = []
for dfpartial in df_original:
    df_list.append(dfpartial)
    df = pd.concat(df_list)

pred_dataset_ori=df

print('Processing Mixed Test Dataset. Real mixed on real-time')
pred_dataset = process_features(pred_dataset_ori)

#también borré las columnas que tenian valores NA
#Para el 3 no lo hace
pred_dataset_ori = pred_dataset_ori.fillna(0)
pred_dataset = pred_dataset.fillna(0)

pred_dataset_ori = pred_dataset_ori.drop('Label', axis=1) 

#para probar los algoritmos
y_pred_mixed = pred_dataset['Label']
X_pred_mixed = pred_dataset.drop('Label', axis=1)

#sc = StandardScaler()
#sc.fit(X_pred_mixed)
#X_pred_mixed_std = sc.transform(X_pred_mixed)


#prueba de algoritmos antes del ensembling
#prueba de algoritmos antes del ensembling

SEED=8
clf1 = LogisticRegression(random_state=SEED)
clf2 = RandomForestClassifier(random_state=SEED)
clf3 = GaussianNB()
clf4 = SVC()
clf5 = KNeighborsClassifier(n_neighbors=3)
clf6 = MLPClassifier((80, 10), early_stopping=False, random_state=SEED)
clf7 = DecisionTreeClassifier()

eclf = joblib.load('modelo_entrenado-1-3-1.pkl')
eclf = eclf.fit (X_pred_mixed,y_pred_mixed)
newlabels = eclf.predict (X_pred_mixed)
#y_pred_mixed['Label'] = newlabels
#df_out = pd.merge (X_pred_mixed, y_pred_mixed[['Label']], how = 'left', left_index = True, right_index = True)
#print (df_out.head(20))
print (newlabels)

pred_dataset_ori['Label'] = newlabels
export_csv=pred_dataset_ori.to_csv ('resultsFase1-dataset1-2-3.csv', index = None, header=True)
print (X_pred_mixed.head(10))

