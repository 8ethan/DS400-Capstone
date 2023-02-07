import findspark
from pyspark.sql import SparkSession
import time


findspark.init('/opt/spark')


# Create Spark session with Kafka configs
print("Creating Spark session...")
spark = SparkSession.builder.appName('SCARP_Kafka_Test')\
                    .config('spark.jars.packages','org.apache.spark:spark-sql-kafka-0-10_2.12:3.0.1')\
                    .config('spark.jars.packages','org.apache.kafka:kafka-clients:2.4.1')\
                    .getOrCreate()
spark.sparkContext.setLogLevel('OFF')

# Create streaming dataframe
print("Creating streaming dataframe")
df = spark.readStream.format("kafka")\
    .option("kafka.bootstrap.servers", "localhost:9092")\
    .option("subscribe", "SCARP_kafka_test2")\
    .option('includeTimestamp', 'true')\
    .load()

data_df = df.select(['value','timestamp'])

# Create stream query
print("Creating stream query")
query = data_df.writeStream\
        .format('memory')\
        .queryName('kafka_test')\
        .start()

# Display query results every 5 seconds
print("Displaying query results")
for x in range(30):
    _df = spark.sql('SELECT * FROM kafka_test')
    _df.show(10)
    time.sleep(5)