"""
Rest API interface file 

vne::tbd:: persist appconfig information in file as well 
vne::tbd:: rbody can be empty and any of json attr may not be present
           rbody may not be of type application/json
           fopen failure handling

           send json body in response for both success and failure
           take backup of config files & cert files before and rollback in case of failure 

           log all incoming requests with json contents with timestamp
           add versioning in this module 
"""

import fileinput
import json
import re
import subprocess
import urllib2

from bottle import route, run, Bottle, request

import appconfig

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


@g_rest_fd.route('/api/v1/connection/mqtt', method='GET')
def get_connection_config():
    """
    read MQTT current appconfig and send in HTTP response 
    """
    print 'GET received'
    if appconfig.get_app_module() != 'web':
        print 'Invalid Module'
        return -1 
    
    
    return "Helloz..."


@g_rest_fd.route('/api/v1/connection/mqtt', method='POST')
def create_connection_config():
    """
    create MQTT connection if it already does not exist
    If it exists already, return error
    vne:: tbd:: which error
         tbd:: module name handling in all CRUD URLs
    """
    
    if appconfig.get_app_module() != 'web':
        print 'Invalid Module'
        return -1 
    
    #Extract JSON payload 
    rbody = json.load(request.body)
    print 'POST received', request, rbody  
    
    retval = process_connection_config(rbody)   
    
    return #str(retval)

@g_rest_fd.route('/api/v1/connection/mqtt', method='PUT')
def update_connection_config():
    """
    update MQTT connection appconfig if it already exists. 
    If it doesn't, return error 
    """
    
    if appconfig.get_app_module() != 'web':
        print 'Invalid Module'
        return -1 
    
    #Extract JSON payload 
    rbody = json.load(request.body)
    print 'PUT received', request, rbody  
    
    retval = process_connection_config(rbody)   
    
    return #str(retval)

@g_rest_fd.route('/api/v1/connection/mqtt', method='DELETE')
def delete_connection_config():
    """
    Delete MQTT Connection appconfig it is already exists
    If it doesn't, return error 
    turn OFF the Nginx as well
    """
    print 'DELETE received'
    if appconfig.get_app_module() != 'web':
        print 'Invalid Module'
        return -1 
    
    #Stop nginx server
    
    return

def process_connection_config(rbody):
    """
    vne::tbd:: 1. take a backup of all modified files and revert back in case of any failure
               2. ensure proper retval at any failure 
    """
    
    retval = 1
    #validate secret token 
    if appconfig.get_auth_token() != rbody['auth_token']: 
        print 'Request Unauthorized', rbody['auth_token'], appconfig.get_auth_token()
        return -1
    
    nginx_file = appconfig.get_nginx_config()
    
    print 'in process_connection_config', nginx_file

    #print rbody
    
    #vne::tbd:: failure of nginx_file opening here
    for line in fileinput.FileInput(nginx_file,inplace=1):

        # if TCP is enabled, update TCP Port    
        if re.search( r'listen(\s*)(.*)\d;$', line, re.M|re.I):
            if rbody['tcp_enabled'] == '1':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + rbody['tcp_port'] + ';')
            elif rbody['tcp_enabled'] == '0':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + '0' + ';')
            else: 
                retval = -1

        # if TLS is enabled, update TLS port 
        if re.search( r'listen(\s*)(.*) ssl;$', line, re.M|re.I): 
            if rbody['tls_enabled'] == '1':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + rbody['tls_port'] + ' ssl;')   
            elif rbody['tls_enabled'] == '0':
                line = line.replace(line,' '*8 + 'listen' + ' '*15 + '0' + ' ssl;')
            else: 
                retval = -1
                
        #ssl_verify_client handling
        if re.search( r'ssl_verify_client(\s*)(.*);', line, re.M|re.I):
            if rbody['tls_enabled'] == '1':
                if rbody['client_auth_enabled'] == '1':
                    line = line.replace(line,' '*8 + 'ssl_verify_client' + ' '*15 + 'on;')   
                elif rbody['client_auth_enabled'] == '0':
                    line = line.replace(line,' '*8 + 'ssl_verify_client' + ' '*15 + 'off;')
                else: 
                    retval = -1
                
        print line.rstrip()
    
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
        subprocess.call(["mv", srv_cert_tmp_file, srv_cert_file])
        subprocess.call(["mv", srv_cert_key_tmp_file, srv_cert_key_file])
        
        if rbody['client_auth_enabled'] == '1':
            file_fp = open(client_cert_tmp_file,"w")
            file_fp.write(rbody['client_ca_cert'])
            file_fp.close()
            process_sslcerts_nginx(client_cert_tmp_file)
            subprocess.call(["mv", client_cert_tmp_file, client_cert_file])
            
    elif rbody['tls_enabled'] == '0':
        print 'TLS disabled, doing nothing..'
    else: 
        retval = -1
    
    #make config changes to nginx server 
    subprocess.call(["service", "nginx", "reload"])
    process_nginx_vmq_req(rbody)
            
    return retval

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
    
    req = urllib2.Request(url, json.dumps(body), headers={'Content-type': 'application/json', 'Accept': 'application/json'})
    response = urllib2.urlopen(req)
    print response.read()
    
    return 1
    
    
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
    print 'GET received'
    
    if appconfig.get_app_module() != 'mqtt':
        print 'Invalid Module'
        return -1 
    
    
    return "Helloz..."


@g_rest_fd.route('/api/v1/internal/vmq', method='POST')
def create_vmq_config():
    """

    """
    
    if appconfig.get_app_module() != 'mqtt':
        print 'Invalid Module'
        return -1 
    
    #Extract JSON payload 
    rbody = json.load(request.body)
    print 'POST received', request, rbody  
    
    retval = process_vmq_config(rbody)   
    
    return #str(retval)

def process_vmq_config(rbody):
    """
    process vmq password list received
    """
    retval = 1
    #validate secret token 
    if appconfig.get_vmq_auth_token() != rbody['auth_token']: 
        print 'Request Unauthorized', rbody['auth_token'], appconfig.get_vmq_auth_token()
        return -1
    
    vmq_config_file = '/etc/vernemq/vernemq.conf'
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
        retval = -1
    
    
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
                    return -1
                line = str(pair.keys()[0]) + ':', str(pair.values()[0]) + '\n'
                fp.write(line[0] + line[1])
            else: 
                if ':' in pair.keys()[0]:
                    return -1
                line = str(pair.keys()[0]) + ':', str(pair.values()[0]) + '\n'
                fp.write(line[0] + line[1])
                break
            
        fp.close()
        ##vne:: take backup of vmq_pwd_file before replacing it
        #print 'pwd file', vmq_tmp_pwd_file
        subprocess.call(["vmq-passwd", "-U", vmq_tmp_pwd_file])
        subprocess.call(["mv", vmq_tmp_pwd_file, vmq_pwd_file])
        
    return retval
            
         
    
