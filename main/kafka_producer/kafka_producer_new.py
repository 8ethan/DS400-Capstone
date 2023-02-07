import socket
from threading import Thread
from kafka import KafkaProducer

        
def on_new_client(c,addr):
        
    rcvdData = bytearray()
    # Recieve all data sent from client.
    while True:
        packet = c.recv(64000000)
        if not packet:
            break
        rcvdData.extend(packet)
    
    # Send recieved data to the kafka topic
    try:
        producer.send(topic_name, rcvdData)
        print("Producer sent data to topic. ", len(rcvdData))
        return True
    except:
        print("Error producing data.")
    
    # Close client connection.
    c.close()
            
            
if __name__ == "__main__":
    
    # Kafka topic name
    topic_name = "SCARP_kafka_test2"

    # Kakfa producer: use same port as the Kafka server
    producer = KafkaProducer(bootstrap_servers=['localhost:9092'], max_request_size=64000000)
    
    # Create server socket and bind to port
    serversocket = socket.socket()
    port = 42069
    serversocket.bind(('', port))
    serversocket.listen(5) 
    
    # Listen for new connections
    while True:
        print("Listening for connections...")
        (clientsocket, address) = serversocket.accept()
        print("Connection From "+str(address))
        
        # Create thread for data processing.
        Thread(target=on_new_client, args=(clientsocket, address)).start()




