import socket
from kafka import KafkaProducer


def on_data(data):
    try:
        producer.send(topic_name, data )
        print("Producer sent data to topic. ", len(data))
        return True

    except:
        print("Error in on_data")
        
if __name__ == "__main__":
    
    # Kafka topics
    topic_name = "SCARP_kafka_test"

    # Kakfa producer: use same port as the Kafka server
    producer = KafkaProducer(bootstrap_servers=['localhost:9092'], max_request_size=64000000)
    
    serversocket = socket.socket()
    port = 42069
    serversocket.bind(('', port))
    
    while True:
        # Check for data
        serversocket.listen(5)
        print("Listening for data...")
        (clientsocket, address) = serversocket.accept()
        print("Connection From "+str(address))
        
        rcvdData = bytearray()
        while True:
            packet = clientsocket.recv(64000000)
            if not packet:
                break
            rcvdData.extend(packet)

        on_data(rcvdData)
        clientsocket.close()



