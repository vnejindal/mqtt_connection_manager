This entity will run on Nginx and MQTT Broker (verneMQ) broker instances

-- Run commands 

Usage: ./start_cm.sh <web|mqtt>
       ./stop_cm.sh

On Nginx instance: 
   $ ./start_cm.sh web 

On verneMQ instance: 
   $ ./start_cm.sh mqtt


-- Config File

   host_ip - Self IP address for REST interface
   rest_port_num - Rest API port number
   auth_token - Secret token between m83 platform and web module
   auth_token_vmq - Secret token between web and mqtt modules 
   vmq_rest_port - MQTT Rest API port number 
   log_file - Log file name (with it absolute path)
   log_level - Log Level (DEBUG|INFO|WARNING|ERROR|CRITICAL)

-- Assumptions:
   1. Only setup having single nginx and single vmq servers is supported so far


