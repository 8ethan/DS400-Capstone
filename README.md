# NetSec
The NetSec Project for SCARP 2022

## Project setup:
1. Set up the environment by following the code at https://github.com/Iretha/IoT23-network-traffic-anomalies-classification. Follow the instructions until run_step01_shuffle_file_content.py.
2. Feature selection experiments are done following the iot23_dataset.py
3. Calculate the accuracy score of machine learning models in categorical_classification.py and iot23_model_prediction.py
4. Make pipelines for applying machine learning models to csv_streaming.py, which predict malware or not by each line.
5. Use csv_streaming.py, csv_kafka_producer.py, and csv_line_sender.py to make inferences from the CSV files made in section 1. 


## Streaming pipeline setup (Step 5):

Step 1: Run csv_streaming.py on the server.

Step 2: Run kafka_producer_new.py also on the server.

Step 3: Computers or IoT devices will need to send their network traffic to the server ip address and port number as specified in the kafka producer script.

The notebook should recive the sent data and perform a prediction on it.
