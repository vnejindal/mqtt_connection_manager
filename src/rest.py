"""
Rest API interface file 

vne::tbd:: persist appconfig information in file as well - done
vne::tbd:: rbody can be empty and any of json attr may not be present - done
           rbody may not be of type application/json - done
          
           send json body in response for both success and failure - done
           log all incoming requests with json contents with timestamp - done
           add versioning in this module 
           create a backup of nginx config file before - done
           create backup of existing certificates and parse nginx command output to 
              replace them back if it fails to load new certs
"""

import fileinput
import json
import re
import subprocess
import urllib2

from bottle import run, Bottle, request

import appconfig
from __builtin__ import False

g_rest_fd = Bottle()


def init_rest():
    """
    REST Interface initialization 
    """
    global g_rest_fd
    #g_rest_fd = Bottle()   
    print 'REST module initialized', g_rest_fd
    
    return 

def start_rest_mod():
    """
    It is a blocking call     
    """
    global g_rest_fd
    print 'Starting REST module'
    appconfig.get_app_logger().info('Starting REST interface, %s:%s', appconfig.get_host_ip(), appconfig.get_rest_port())
    run(g_rest_fd, host=appconfig.get_host_ip(), port=appconfig.get_rest_port())
    
#################### NGINX WEB SERVER MODULE ##########################
"""
HTTP METHODS: POST(create), PUT(Edit), DELETE(Delete), GET(Read)
APIs: 
/api/v1/connection/mqtt
{
    "auth_token":"secret",
    "connection name":"test_conn",
    "tcp_enabled":"1",
    "tcp_port": "885",
    "tls_enabled":"1",
    "tls_port":"8882",
    "server_cert_key":"ABCDER1234",
    "server_cert":"ABCDER1234",
    "client_auth_enabled":"0",
    "client_ca_cert": "ABCDER1234",
    "user_auth_enabled":integer,
    "user_auth_list":
    [
        {
            "user1":"pass1"
        },
        {
            "user2":"pass2"
        }
    ]
}

"""


@g_rest_fd.route('/api/v1/connection/mqtt', method='GET')
def get_connection_config():
    """
    read MQTT current appconfig and send in HTTP response 
    """
    #print 'GET received'
    try: 
        if appconfig.get_app_module() != 'web':
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" }   
        
        return { "success" : False, "error" : "Not Implemented" }
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }
    

@g_rest_fd.route('/api/v1/connection/mqtt', method='POST')
def create_connection_config():
    """
    create MQTT connection
    """
    try:         
        if appconfig.get_app_module() != 'web':
            #print 'Invalid Module'
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" }
    
        #Extract JSON payload 
        rbody = json.load(request.body)
        appconfig.get_app_logger().info('POST received, %s:%s', request, rbody)
        #print 'POST received', request, rbody  
    
        return process_connection_config(rbody)
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }
    

@g_rest_fd.route('/api/v1/connection/mqtt', method='PUT')
def update_connection_config():
    """
    update MQTT connection appconfig if it already exists. 
    If it doesn't, return error 
    """
    
    if appconfig.get_app_module() != 'web':
        #print 'Invalid Module'
        appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request" } 
    
    try:
        #Extract JSON payload 
        rbody = json.load(request.body)
        #print 'PUT received', request, rbody  
        appconfig.get_app_logger().info('PUT received, %s:%s', request, rbody)
    
        return process_connection_config(rbody)   
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }
    

@g_rest_fd.route('/api/v1/connection/mqtt', method='DELETE')
def delete_connection_config():
    """
    Delete MQTT Connection appconfig it is already exists
    If it doesn't, return error 
    turn OFF the Nginx as well
    """
    #print 'DELETE received'
    try: 
        if appconfig.get_app_module() != 'web':
            #print 'Invalid Module'
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" } 
        
        #vne:: tbd: Stop Nginx server
        return { "success" : False, "error" : "Not Implemented" }
    except:
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url) 
        return { "success" : False, "error" : "Invalid Request. Some Exception" }    
    

def process_connection_config(rbody):
    """
     1. take a backup of all modified files and revert back in case of any failure
               2. ensure proper retval at any failure 
    """
    
    retval = True
    err_str = 'None'
    #validate secret token 
    if appconfig.get_mqtt_auth_token() != rbody['auth_token']: 
        appconfig.get_app_logger().error('Request Unauthorized, %s:%s', rbody['auth_token'], appconfig.get_mqtt_auth_token())
        #print 'Request Unauthorized', rbody['auth_token'], appconfig.get_mqtt_auth_token()
        return { "success" : False, "error" : "Request Unauthorized" }
    
    nginx_file = appconfig.get_nginx_config()
    nginx_tmp_file = appconfig.get_tmp_path() + nginx_file.split('/')[-1]

    appconfig.get_app_logger().debug('copying %s %s', nginx_file, nginx_tmp_file)
    subprocess.call(["cp", nginx_file, nginx_tmp_file])
    
    #print 'in process_connection_config', nginx_file

    #print rbody
    #failure of nginx_file opening here
    #create a backup of nginx config file before
    for line in fileinput.FileInput(nginx_file,inplace=1):

        # if TCP is enabled, update TCP Port    
        if re.search( r'listen(\s*)(.*)\d;$', line, re.M|re.I):
            if rbody['tcp_enabled'] == '1':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + rbody['tcp_port'] + ';')
            elif rbody['tcp_enabled'] == '0':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + '0' + ';')
            else: 
                retval = False; err_str = 'tcp_enabled ' + rbody['tcp_enabled']
                break

        # if TLS is enabled, update TLS port 
        if re.search( r'listen(\s*)(.*) ssl;$', line, re.M|re.I): 
            if rbody['tls_enabled'] == '1':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + rbody['tls_port'] + ' ssl;')   
            elif rbody['tls_enabled'] == '0':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + '0' + ' ssl;')
            else:
                retval = False; err_str = 'tls_enabled ' + rbody['tls_enabled']
                break
                
        #ssl_verify_client handling
        if re.search( r'ssl_verify_client(\s*)(.*);', line, re.M|re.I):
            if rbody['tls_enabled'] == '1':
                if rbody['client_auth_enabled'] == '1':
                    line = line.replace(line,' '*8 + 'ssl_verify_client' + ' '*15 + 'on;')   
                elif rbody['client_auth_enabled'] == '0':
                    line = line.replace(line,' '*8 + 'ssl_verify_client' + ' '*15 + 'off;')
                else: 
                    retval = False; err_str = 'client_auth_enabled ' + rbody['client_auth_enabled']
                    break
                
        print line.rstrip()
    
    if retval is False: 
        #overwrite original file and return from here only 
        subprocess.call(["cp", nginx_tmp_file, nginx_file] )
        return {"success" : retval, "error" : err_str }
        
    srv_cert_file = appconfig.get_server_cert_file() 
    srv_cert_key_file = appconfig.get_server_cert_key_file()
    client_cert_file = appconfig.get_client_cert_file()

    srv_cert_tmp_file = appconfig.get_tmp_path() + srv_cert_file.split('/')[-1]
    srv_cert_key_tmp_file = appconfig.get_tmp_path() + srv_cert_key_file.split('/')[-1]
    client_cert_tmp_file = appconfig.get_tmp_path() + client_cert_file.split('/')[-1]
    
    # update certificates 
    if rbody['tls_enabled'] == '1':
        #update server cert files 
        file_fp = open(srv_cert_tmp_file,"w")
        file_fp.write(rbody['server_cert'])
        file_fp.close()
        
        file_fp = open(srv_cert_key_tmp_file,"w")
        file_fp.write(rbody['server_cert_key'])
        file_fp.close()
        
        process_sslcerts_nginx(srv_cert_tmp_file)
        process_sslcerts_nginx(srv_cert_key_tmp_file)

        appconfig.get_app_logger().debug('copying %s %s', srv_cert_tmp_file, srv_cert_file)
        appconfig.get_app_logger().debug('copying %s %s', srv_cert_key_tmp_file, srv_cert_key_file)
        subprocess.call(["cp", srv_cert_tmp_file, srv_cert_file])
        subprocess.call(["cp", srv_cert_key_tmp_file, srv_cert_key_file])
        
        if rbody['client_auth_enabled'] == '1':
            file_fp = open(client_cert_tmp_file,"w")
            file_fp.write(rbody['client_ca_cert'])
            file_fp.close()
            process_sslcerts_nginx(client_cert_tmp_file)
            subprocess.call(["cp", client_cert_tmp_file, client_cert_file])
            
    elif rbody['tls_enabled'] == '0':
        #print 'TLS disabled, doing nothing..'
        pass
    else: 
        retval = False; err_str = 'tls_enabled ' + rbody['tls_enabled'] 
    
    #make config changes to nginx server 
    if retval is not False: 
        #vne:: tbd: check the status and start if nginx is not already running
        subprocess.call(["service", "nginx", "reload"])
        return process_nginx_vmq_req(rbody)
    else:             
        return {"success" : retval, "error" : err_str }

def process_sslcerts_nginx(filename):
    """
    This function changes certificate and private key files to a format which is parsed by Nginx module
    -----BEGIN PRIVATE KEY-----
    -----END PRIVATE KEY----- 
    
    -----BEGIN CERTIFICATE-----
    -----END CERTIFICATE-----
    
    """

    file_fp = open(filename,"r")
    file_str = file_fp.read()
    file_fp.close()

    #print 'processing ', filename, file_str
    
    cert_type = ''
    
    ## Check if it contains PRIVATE KEY or CERTIFICATE string 
    if 'PRIVATE KEY' in file_str:
        cert_type = 'key'
    elif 'CERTIFICATE' in file_str:
        cert_type = 'cert'
    else: 
        return -1

    #print cert_type
 
    if cert_type == 'key':
        pass
        file_str = file_str.replace("-----BEGIN PRIVATE KEY-----", "\n-----BEGIN PRIVATE KEY-----\n")
        file_str = file_str.replace("-----END PRIVATE KEY-----", "\n-----END PRIVATE KEY-----")
    else: 
        pass
        file_str = file_str.replace("-----BEGIN CERTIFICATE-----", "\n-----BEGIN CERTIFICATE-----\n")
        file_str = file_str.replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----")
    
    file_fp = open(filename, "w")
    file_fp.write(file_str)
    file_fp.close()
    
    return 1
    


def process_nginx_vmq_req(rbody):
    """
    This function will send HTTP POST request to vmq node for user auth handling
    
    """
    
    vmq_port = appconfig.get_vmq_rest_port()
    vmq_auth_token = appconfig.get_vmq_auth_token()
    vmq_srv_ip = appconfig.get_upstream_mqtt_server()
    
    url = 'http://' + vmq_srv_ip + ':' + str(vmq_port) + '/api/v1/internal/vmq'
    
    body = {}
    body['auth_token'] = vmq_auth_token
    body['user_auth_enabled'] = rbody['user_auth_enabled']
    body['user_auth_list'] = rbody['user_auth_list']
    json_body = json.dumps(body)
    
    appconfig.get_app_logger().info('Sending REST API to vmq, %s, %s', url, json_body)
    
    req = urllib2.Request(url, json_body, headers={'Content-type': 'application/json', 'Accept': 'application/json'})
    response = urllib2.urlopen(req)
    appconfig.get_app_logger().info("Got response from vmq, %s", response.read())
    
    return { "success" : True, "error" : "None" }
    
    
#################### VERNEMQ MQTT SERVER MODULE ##########################
"""
HTTP METHODS: POST(create),GET(Read)
APIs: 
{
    "auth_token":string,
    "user_auth_enabled":integer,
    "user_auth_list":
    [
        {
            username:"user1",
            password:"pass1",
        },
        {
            username:"user2",
            password:"pass2",
        }
    ]
}

"""

@g_rest_fd.route('/api/v1/internal/vmq', method='GET')
def get_vmq_config():
    """

    """
    #print 'GET received'
    
    try:
        if appconfig.get_app_module() != 'mqtt':
            #print 'Invalid Module'
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" }
        
        return { "success" : False, "error" : "Not Implemented" }
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }
    
    
@g_rest_fd.route('/api/v1/internal/vmq', method='POST')
def create_vmq_config():
    """

    """
    try:
        if appconfig.get_app_module() != 'mqtt':
            #print 'Invalid Module'
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" } 
    
        #Extract JSON payload 
        rbody = json.load(request.body)
        #print 'POST received', request, rbody  
        appconfig.get_app_logger().info('POST received, %s:%s', request, rbody)
    
        return process_vmq_config(rbody)   
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }

def process_vmq_config(rbody):
    """
    process vmq password list received
    """
    retval = True
    err_str = 'None'
    #validate secret token 
    if appconfig.get_vmq_auth_token() != rbody['auth_token']: 
        #print 'Request Unauthorized', rbody['auth_token'], appconfig.get_vmq_auth_token()
        appconfig.get_app_logger().error('Request Unauthorized, %s:%s', rbody['auth_token'], appconfig.get_vmq_auth_token())
        return { "success" : False, "error" : "Request Unauthorized" }
    
    vmq_config_file = '/etc/vernemq/vernemq.conf'
    vmq_config_tmp_file = appconfig.get_tmp_path() + vmq_config_file.split('/')[-1]
    subprocess.call(["cp", vmq_config_file, vmq_config_tmp_file] )
    
    vmq_pwd_file = ''
    vmq_tmp_pwd_file = appconfig.get_tmp_path()
    
    """
    username validation - must not contain ':'
    vne:: tbd: create backup of file 
    update: allow_anonymous = on
            use command sudo vmq-admin set allow_anonymous=on
            update vmq_config_file to persist changes 
    
    get: vmq_passwd.password_file = /etc/vernemq/vmq.passwd
    vne:: tbd: create backup of password file 
    create new password file: using rbody payload 
    overwrite password file using sudo command 
    
    vne::tbd:: restore file to original state in case of any failure
    """
    
    # if user_auth_enabled is 0, enable anonymous mode 
    if rbody['user_auth_enabled'] == '1':
        subprocess.call(["vmq-admin", "set", "allow_anonymous=off"])
        
        for line in fileinput.FileInput(vmq_config_file,inplace=1):
            if re.search( r'allow_anonymous =(.*)', line, re.M|re.I):
                line = line.replace(line,'allow_anonymous = off')
            print line.rstrip()
            
    elif rbody['user_auth_enabled'] == '0':
        subprocess.call(["vmq-admin", "set", "allow_anonymous=on"])
        
        for line in fileinput.FileInput(vmq_config_file,inplace=1):
            if re.search( r'allow_anonymous =(.*)', line, re.M|re.I):
                line = line.replace(line,'allow_anonymous = on')
            print line.rstrip()
    else:
        retval = False; err_str = 'user_auth_enabled', rbody['user_auth_enabled']
    
    if retval is False: 
        #overwrite original file and return from here only 
        subprocess.call(["cp", vmq_config_tmp_file, vmq_config_file])
        return {"success" : retval, "error" : err_str }
    
    if rbody['user_auth_enabled'] == '1':
    
        fp = open(vmq_config_file, "r")
        for line in fp:
            sobj = re.search(r'vmq_passwd.password_file = (.*)', line, re.M|re.I)
            if sobj: 
                vmq_pwd_file = sobj.group(1).rstrip()
                #print 'vmq pwd file ', vmq_pwd_file
                break
    
        fp.close()
    
        #vmq_tmp_pwd_file.append(vmq_pwd_file.split('/')[-1])
        vmq_tmp_pwd_file = vmq_tmp_pwd_file + vmq_pwd_file.split('/')[-1]
        #print 'tmp owd file: ', vmq_tmp_pwd_file, rbody['user_auth_list']

        fp = open(vmq_tmp_pwd_file, "w")
        while True:
            pair = rbody['user_auth_list'].pop()
            if len(rbody['user_auth_list']) != 0:
                if ':' in pair.keys()[0]:
                    retval = False; err_str = 'Invalid User ', pair.key()[0]
                    break
                line = str(pair.keys()[0]) + ':', str(pair.values()[0]) + '\n'
                fp.write(line[0] + line[1])
            else: 
                if ':' in pair.keys()[0]:
                    retval = False; err_str = 'Invalid User ', pair.key()[0]
                    break
                line = str(pair.keys()[0]) + ':', str(pair.values()[0]) + '\n'
                fp.write(line[0] + line[1])
                break
            
        fp.close()
        ##vne:: take backup of vmq_pwd_file before replacing it
        #print 'pwd file', vmq_tmp_pwd_file
        if retval is not False: 
            subprocess.call(["vmq-passwd", "-U", vmq_tmp_pwd_file])
            subprocess.call(["mv", vmq_tmp_pwd_file, vmq_pwd_file])
        
    return {"success" : retval, "error" : err_str }
            

#################### KAFKA CONNECT SERVER MODULE ##########################      
"""
{
 "name" : "test-1",
 "config" : {
     "connector.class": "com.incs83.kafka.connect.mqtt.MqttSourceConnector",
     "mqtt.server_uris": "ssl://18.221.86.121:8883",
     "tasks.max": "2",
     "name": "test-1",
     "kafka.topic": "TEST",
     "mqtt.clean_session": "true",
     "mqtt.user" : "user1",
     "mqtt.password" : "pass1",
     "mqtt.ssl.ca_cert" : "/var/lib/hadoop-hdfs/mqtt-tls/root.crt",
     "mqtt.ssl.cert" : "/var/lib/hadoop-hdfs/mqtt-tls/client.crt",
     "mqtt.ssl.key" : "/var/lib/hadoop-hdfs/mqtt-tls/client.key",
     "mqtt.topic": "TEST_VNE_REPORT",
     "mqtt.connection_timeout": "150000",
     "mqtt.keep_alive_interval": "150000",
     "mqtt.auto_reconnect": "true",
     "offset.flush.interval.ms": "600000",
     "offset.flush.timeout.ms": "600000",
     "request.timeout.ms": "600000"
 }
}

create a connector 
delete a connector 
get a connector config
edit a connector 
get list of all connectors 

   API body: 
    TCP 
     "name": "test-1",
     "mqtt.server_uri": "tcp://18.221.86.121:1883",
     "mqtt.user" : "user1", #if present
     "mqtt.password" : "pass1", #if present 
     "mqtt.topic": "TEST_VNE_REPORT",


    TLS 
     "name": "test-1",
     "mqtt.server_uri": "ssl://18.221.86.121:8883",
     "mqtt.user" : "user1",
     "mqtt.password" : "pass1",
     "mqtt.ssl.ca_cert" : "/var/lib/hadoop-hdfs/mqtt-tls/root.crt",
     "mqtt.ssl.cert" : "/var/lib/hadoop-hdfs/mqtt-tls/client.crt",
     "mqtt.ssl.key" : "/var/lib/hadoop-hdfs/mqtt-tls/client.key",
     "mqtt.topic": "TEST_VNE_REPORT",

    
  
"""




@g_rest_fd.route('/api/v1/internal/kconnect', method='GET')
def get_kconnect_config():
    """
    return all config of kafka connect connectors
    vne::tbd:: validate auth token
    """
    try:
        if appconfig.get_app_module() != 'kconnect':
            #print 'Invalid Module'
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" } 
    
        #print 'GET received', request, rbody  
        appconfig.get_app_logger().info('GET received, %s', request)
    
        return { "success" : True, "config": json.dumps(appconfig.get_kconnect_config()) }   
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }


@g_rest_fd.route('/api/v1/internal/kconnect', method='POST')
def create_kconnect_connector(): 
    """
    create a new kafka connect connector 
    """
    try:
        if appconfig.get_app_module() != 'kconnect':
            #print 'Invalid Module'
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" } 
    
        #Extract JSON payload 
        rbody = json.load(request.body)
        #print 'POST received', request, rbody  
        appconfig.get_app_logger().info('POST received, %s:%s', request, rbody)
    
        return process_create_kconnect(rbody)   
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }


@g_rest_fd.route('/api/v1/internal/kconnect', method='DELETE')
def delete_kconnect_connector(): 
    """
    delete kafka connect connector 
    """
    try:
        if appconfig.get_app_module() != 'kconnect':
            #print 'Invalid Module'
            appconfig.get_app_logger().error('Invalid Module, %s, %s', appconfig.get_app_module(), request.url)
            return { "success" : False, "error" : "Invalid Request" } 
    
        #Extract JSON payload 
        rbody = json.load(request.body)
        #print 'POST received', request, rbody  
        appconfig.get_app_logger().info('DELETE received, %s:%s', request, rbody)
    
        return process_delete_kconnect(rbody)   
    except: 
        appconfig.get_app_logger().exception('Invalid Request. Some Exception, %s, %s', appconfig.get_app_module(), request.url)
        return { "success" : False, "error" : "Invalid Request. Some Exception" }

def process_delete_kconnect(rbody):
    """
    
    """
    retval = True
    err_str = 'None'
    #validate secret token 
    if appconfig.get_kconnect_auth_token() != rbody['auth_token']: 
        #print 'Request Unauthorized', rbody['auth_token'], appconfig.get_kconnect_auth_token()
        appconfig.get_app_logger().error('Request Unauthorized, %s:%s', rbody['auth_token'], appconfig.get_kconnect_auth_token())
        return { "success" : False, "error" : "Request Unauthorized" }
    
    ## Application Logic 
    
    if rbody['name'] not in appconfig.get_kconnect_config().keys():
        appconfig.get_app_logger().error('Connector does not exist, %s', rbody['name'])
        return { "success" : False, "error" : "Connector does not exist" }
    else: 
        # Send Delete request to KC 
        retval, err_str = send_kconnect_kc_req(rbody, 'DELETE')
        # create new connector file and dump file there, if success from send_kconnect_kc_req
        if retval == 'success':
            appconfig.update_kconnect_config(rbody['name'], rbody, 'DELETE')
        else: 
            pass #vne::tbd:: remove cert files if created
    
    return {"success" : retval, "error" : err_str }



def process_create_kconnect(rbody):
    """
    
    """
    retval = True
    err_str = 'None'
    #validate secret token 
    if appconfig.get_kconnect_auth_token() != rbody['auth_token']: 
        #print 'Request Unauthorized', rbody['auth_token'], appconfig.get_kconnect_auth_token()
        appconfig.get_app_logger().error('Request Unauthorized, %s:%s', rbody['auth_token'], appconfig.get_kconnect_auth_token())
        return { "success" : False, "error" : "Request Unauthorized" }
    
    ## Application Logic 
    
    if rbody['name'] in appconfig.get_kconnect_config().keys():
        appconfig.get_app_logger().error('Connector already exists, %s', rbody['name'])
        return { "success" : False, "error" : "Connector already exists" }
    else: 
        rbody_keyl = ['mqtt.ssl.ca_cert', 'mqtt.ssl.cert', 'mqtt.ssl.key']
        
        #TLS Support 
        for rbody_key in rbody_keyl:
            if rbody_key in rbody.keys():
                cert_file = appconfig.get_kconnect_cert_path() + rbody_key
                file_fp = open(cert_file,"w")
                file_fp.write(rbody[rbody_key])
                file_fp.close()
                process_sslcerts_nginx(cert_file)
                rbody[rbody_key] = cert_file
        
        retdict = send_kconnect_kc_req(rbody, 'POST')
        
        print retdict
        # create new connector file and dump file there, if success from send_kconnect_kc_req
        if retdict['success'] is True:
            appconfig.update_kconnect_config(rbody['name'], rbody, 'CREATE')
        else: 
            pass #vne::tbd:: remove cert files if created
    
    return {"success" : retdict['success'], "error" : retdict['error'] }

def send_kconnect_kc_req(rbody, rmethod = 'POST'):
    """
    This function will send HTTP POST request to vmq node for user auth handling
    
    """
    body = {}
    url = 'http://' + appconfig.get_kconnect_kc_url() + '/connectors'
    
  
    if rmethod == 'DELETE':
        url = url + '/' + rbody['name']    
    elif rmethod == 'POST':
        body['name'] = rbody['name']
        body['config'] = {}
        body['config']['connector.class'] = 'com.evokly.kafka.connect.mqtt.MqttSourceConnector'
        body['config']['tasks.max'] = '2'
        body['config']['kafka.topic'] = appconfig.get_kconnect_kafka_topic()
        body['config']['mqtt.clean_session'] = 'true'
        body['config']['mqtt.connection_timeout'] = '150000'
        body['config']['mqtt.keep_alive_interval'] = '150000'
        body['config']['mqtt.auto_reconnect'] = 'true'
        body['config']['offset.flush.interval.ms'] = '60000'
        body['config']['offset.flush.timeout.ms'] = '60000'
        body['config']['request.timeout.ms'] = '50000'
        
        body['config']['name'] = rbody['name']
        body['config']['mqtt.server_uris'] = rbody['mqtt.server_uri']
        body['config']['mqtt.topic'] = rbody['mqtt.topic']  
        if 'mqtt.user' in rbody.keys() and 'mqtt.password' in rbody.keys():
            body['config']['mqtt.user'] = rbody['mqtt.user']
            body['config']['mqtt.password'] = rbody['mqtt.password']
        
        rbody_keyl = ['mqtt.ssl.ca_cert', 'mqtt.ssl.cert', 'mqtt.ssl.key']
        
        for rbody_key in rbody_keyl:
            if rbody_key in rbody.keys():
                body['config'][rbody_key] = rbody[rbody_key]
            
    
    
    json_body = json.dumps(body)
    appconfig.get_app_logger().info('Sending REST API to kakfa-connect, %s %s, %s', rmethod, url, json_body)
    
    req = urllib2.Request(url, data = json_body, headers={'Content-type': 'application/json', 'Accept': 'application/json'})
    req.get_method = lambda: rmethod
    response = urllib2.urlopen(req)
    appconfig.get_app_logger().info("Got response from kafka-connect, %s", response.read())
    
    #vne::tbd check if response is 200 OK with error_code not present; fallback 
    return { "success" : True, "error" : "None" }
    

