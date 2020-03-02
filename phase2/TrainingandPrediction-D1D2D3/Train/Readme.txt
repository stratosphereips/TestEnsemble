Scripts description:
obtain_training_testing_forphase2.py: separate the dataset resultsFase1conrandom-dataset1-2-3.csv for training (80%) and testing(20%)
decisionForEachIpSrc-IPDstBasedinPercenteges.py: this scripts take a decision for each pair IPSrc-IPDst based on 
their labels for TCPEstabliished connections, TCPNoEstablished connections, UDPEstablished connections and UDPNoEstablished connections.
The criteria to decide if a pair IPSrc-IPDst is part of an infection (labeled as infected) is the percentege of malicious flows is greater than a threshold (we use the number of flows of this type too). In this script we use differents values for percenteges and counters to choose the values and we obtain differents results.


