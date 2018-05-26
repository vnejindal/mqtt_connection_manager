This entity will run on Nginx and MQTT Broker (verneMQ) broker instances

-- Run commands 

Usage: ./start_cm.sh <web|mqtt|kconnect>
       ./stop_cm.sh

On Nginx instance: 
   $ ./start_cm.sh web 

On verneMQ instance: 
   $ ./start_cm.sh mqtt

On Kafka Connect instance: 
   $ ./start_cm.sh kconnect


-- Config File

   host_ip - Self IP address for REST interface
   rest_port_num - Rest API port number
   auth_token - Secret token between m83 platform and web module
   auth_token_vmq - Secret token between web and mqtt modules 
   auth_token_kconnect - Secret token between m83 platform and kconnect modules
   vmq_rest_port - MQTT Rest API port number 
   log_file - Log file name (with it absolute path)
   log_level - Log Level (DEBUG|INFO|WARNING|ERROR|CRITICAL)
   kconnect_kafka_topic - Kafka Topic used for Kafka Connect MQTT connector
   
-- Assumptions:
   1. Only setup having single nginx and single vmq servers is supported so far
   2. Single KC in method83 deployment 
=========================
	APIs - MQTT 
=========================

HTTP POST/PUT: <ip>:<rest_port_num>/api/v1/connection/mqtt

{
    "auth_token":<auth_token_mqtt>,
    "connection name":"test_conn",
    "tcp_enabled":"1",
    "tcp_port": "1883",
    "tls_enabled":"1",
    "tls_port":"8888",
    "server_cert_key":"-----BEGIN PRIVATE KEY-----+PrMq2g==-----END PRIVATE KEY-----",
    "server_cert":"-----BEGIN CERTIFICATE-----MIIFMjCCBBqgAWeCtWVYpoNz4iCxTIM5CufReYNnyicsbkqWletNw+vHX/bvZ8=-----END CERTIFICATE-----",
    "client_auth_enabled":"1",
    "client_ca_cert": "-----BEGIN CERTIFICATE-----MIIFMjCCBBqgAWeCtWVYpoNz4iCxTIM5CufReYNnyicsbkqWletNw+vHX/bvZ8=-----END CERTIFICATE-----",
    "user_auth_enabled":"1",
    "user_auth_list":
    [
        {"user1":"pass1"},
        {"user3":"pass3"}
    ]
}

=========================
	APIs - VERNEMQ
=========================

HTTP POST: <ip addr>:<vmq_rest_port>/api/v1/internal/vmq
 

{
    "auth_token":<auth_token_vmq>,
    "user_auth_enabled":"1",
    "user_auth_list":
    [
        {"user1":"pass1"},
        {"user2":"pass2"}
    ]
}

=========================
	APIs - KCONNECT
=========================

HTTP GET/POST/PUT: <ip addr>:<rest_port_num>/api/v1/internal/kconnect


{
    "auth_token":<auth_token_kconnect>,
    "name": "test-1",
     "mqtt.server_uri": "tcp://18.221.86.121:1883",
     "mqtt.user" : "user1",
     "mqtt.password" : "pass1", 
     "mqtt.topic": "TEST_VNE_REPORT",
     "mqtt.ssl.ca_cert" : "-----BEGIN CERTIFICATE-----MIIFMjCCBBqgAWeCtWVYpoNz4iCxTIM5CufReYNnyicsbkqWletNw+vHX/bvZ8=-----END CERTIFICATE-----",
     "mqtt.ssl.cert" : "-----BEGIN CERTIFICATE-----MIIFMjCCBBqgAWeCtWVYpoNz4iCxTIM5CufReYNnyicsbkqWletNw+vHX/bvZ8=-----END CERTIFICATE-----",
     "mqtt.ssl.key" : "-----BEGIN PRIVATE KEY-----+PrMq2g==-----END PRIVATE KEY-----"
}

HTTP DELETE is implemented using query params due to platform java library limitation
In case of DELETE, only auth_token and name are required in payload
Example:     api/v1/internal/kconnect?authToken=<secret>&name=<connector name>
      use + in case of query params
