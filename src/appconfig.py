"""

Config file handling

"""
import json
import re
import os
import threading
from time import sleep
import urllib2
import rest
import sys 
sys.path.append('nginxparser')

from nginxparser import NginxParser, load,  dumps

import applog


g_config = {}


def init_appconfig(json_file):
    global g_config
    #initialize logger module 
    g_config.update(get_json_config(json_file))
    g_config['logger'] = applog.init_applog(g_config['log_file'],g_config['log_level'])
    g_config['tmp_path'] = 'tmp/'
    
    if not os.path.exists(g_config['tmp_path']):
        os.makedirs(g_config['tmp_path'])
    
    if get_app_module() == 'web':
        load_nginx_params_v1()
    elif get_app_module() == 'kconnect':
        init_kconnect_config()
    print 'Config loaded'
    print g_config
    g_config['logger'].info("Config: %s", g_config)
    return 

def init_kconnect_config():
    """
    vne::tbd:: 
       load connector config files if they exist
       check config in kc if it is the same else change it
       failure handling - self failure and reboot, KC failure and reboot
    """
    global g_config
    cpath = g_config['tmp_path'] + 'connectors/'
    if not os.path.exists(cpath):
        os.makedirs(cpath) 
    
    certpath = g_config['tmp_path'] + 'certs/'
    if not os.path.exists(certpath):
        os.makedirs(certpath) 
        
    g_config['kconnect_path'] = cpath
    g_config['kconnect_cert_path'] = certpath
    # KC REST URL ; Hardcoding it as it will run on same machine
    g_config['kconnect_kc_url'] = '127.0.0.1:8083'
    g_config['kconnect_config'] = {}
    
    for filename in os.listdir(get_kconnect_path()):
        fp = open(get_kconnect_path() + filename, 'r')
        get_kconnect_config()[filename] = json.loads(fp.read())
        get_app_logger().info('loaded kconnect config for %s, %s', filename, get_kconnect_config()[filename])
        fp.close()
        
    get_app_logger().info("Starting thread for kc sync")
    g_config['kconnect_sync_thread'] = threading.Thread(target=kconnect_sync_thread, args=(15,))
   
    return

def kconnect_sync_thread(stime):
    
    global g_config

    url = 'http://' + get_kconnect_kc_url() + '/connectors'
    while True:
        sleep(stime)
        req = urllib2.Request(url)
        req.get_method = lambda: 'GET'
#        get_app_logger().info("kconnect sync thread running %s", url)
        #vne::tbd:: put try catch here; While loop must not exit for any reason
        try: 
            response = urllib2.urlopen(req)
        except urllib2.URLError as e:
            get_app_logger().error("error resp from kafka-connect %s", e.reason)
            continue
        
        resp_json = response.read()
#        get_app_logger().info("Got response from kafka-connect, %s %d", resp_json, len(resp_json))
        
        #if len(resp_json) != len(get_kconnect_config().keys()):
        if len(resp_json) == 2:
            # KC out of sync , sync it
#            get_app_logger().info("kafka-connect out of sync, syncing it..")
            for key in get_kconnect_config().keys():
                rest.send_kconnect_kc_req(get_kconnect_config()[key], 'POST')
                

def load_nginx_params_v1():
    """
    Uses nginxparser module 
    nginx_config : Runtime nginx_config 
    nginx_config_base : config picked from base nginx file
    """
    global g_config
    
    #nginx_fp = open(get_nginx_config(), "r")
    nginx_config = load(open(get_nginx_config()))
    g_config['nginx_config'] = nginx_config
    
    nginx_config_base = load(get_tmp_path() + '/stream.conf')
    g_config['nginx_config_base'] = nginx_config_base
    
    set_nginx_upstream_mqtt_server()
    
    
    ## Assumes stream.conf file in order
    ## upstream block 
    ## TCP stream block 
    ## TLS stream block 
    
    g_config['ssl_certificate'] = '/'.join([os.getcwd(), get_tmp_path() + 'server.crt']) 
    g_config['ssl_certificate_key'] = '/'.join([os.getcwd(), get_tmp_path() + 'server.key'])
    g_config['ssl_client_certificate'] = '/'.join([os.getcwd(), get_tmp_path() + 'client.crt'])
    g_config['upstream_mqtt_server'] = get_nginx_upstream_mqtt_server()
    
    return 

def load_nginx_params():
    """
    reads TLS files info from provisioned nginx conf file 
    """
    global g_config
    
    nginx_fp = open(get_nginx_config(), "r")
        
    for line in nginx_fp:
        #print line
        sobj = re.search(r'ssl_certificate\b( *)(.*);', line, re.M|re.I)
        if sobj:
            g_config['ssl_certificate'] = sobj.group(2)
        sobj = re.search(r'ssl_certificate_key( *)(.*);', line, re.M|re.I)
        if sobj:
            g_config['ssl_certificate_key'] = sobj.group(2)
        sobj = re.search(r'ssl_client_certificate( *)(.*);', line, re.M|re.I)
        if sobj:
            g_config['ssl_client_certificate'] = sobj.group(2)
        sobj = re.search(r'server\b( *)(.*):(.*)', line, re.M|re.I)
        if sobj:
            g_config['upstream_mqtt_server'] = sobj.group(2)
    nginx_fp.close()
    return 
 
def get_json_config(json_file):
    """
    returns json object of a json file
    """
    fp = open(json_file)
    
    json_config = fp.read()
    fp.close()
    return json.loads(json_config)

def set_app_module(mod_name):
    global g_config
    g_config['module'] = mod_name
    
def get_app_module():
    global g_config
    return g_config['module']

def get_host_ip():
    global g_config
    return g_config['host_ip']

def get_rest_port():
    global g_config
    if get_app_module() == 'web':
        return g_config['rest_port_num']
    else:
        return get_vmq_rest_port()

def get_nginx_config():
    global g_config
    return g_config['nginx_file']

def get_nginx_upstream_mqtt_server():
    global g_config
    return g_config['nginx_config'][0][1][0][1].split(':')[0]

def set_nginx_upstream_mqtt_server():
    global g_config
    g_config['nginx_config_base'][0][1][0][1] = get_nginx_upstream_mqtt_server() + ':1883'
    
def set_nginx_tcp_port(port_num):
    global g_config
    g_config['nginx_config_base'][1][1][0][1] = str(port_num)

def set_nginx_ssl_port(port_num):
    global g_config
    g_config['nginx_config_base'][2][1][0][1] = str(port_num) + ' ssl'

def set_nginx_verify_client(cauth):
    global g_config
    if cauth == '1':
        g_config['nginx_config_base'][2][1][10][1] = 'on'
    elif cauth == '0':
        g_config['nginx_config_base'][2][1][10][1] = 'off'

def create_nginx_config():
    global g_config
    g_config.pop('nginx_config', None)
    g_config['nginx_config'][0] = g_config['nginx_config_base'][0]

def set_nginx_config(type = 'tcp'):
    """
    type = tcp, tls , both 
    """
    global g_config
    if type == 'tcp' or type == 'both':
        g_config['nginx_config'][1] = g_config['nginx_config_base'][1]
    if type == 'tls':
        g_config['nginx_config'][2] = g_config['nginx_config_base'][2]

def nginx_config_dump():
    global g_config
    fp = open(get_nginx_config(), 'w')
    fp.write(dumps(g_config['nginx_config']))
    fp.close()

def get_mqtt_auth_token():
    global g_config
    return g_config['auth_token_mqtt']

def get_vmq_auth_token():
    global g_config
    return g_config['auth_token_vmq']

def get_kconnect_auth_token():
    global g_config
    return g_config['auth_token_kconnect']

def get_server_cert_file():
    global g_config
    return g_config['ssl_certificate']

def get_server_cert_key_file():
    global g_config
    return g_config['ssl_certificate_key']

def get_client_cert_file():
    global g_config
    return g_config['ssl_client_certificate']

def get_upstream_mqtt_server():
    global g_config
    return g_config['upstream_mqtt_server']

def get_tmp_path():
    global g_config 
    return g_config['tmp_path']

def get_vmq_rest_port():
    global g_config
    return g_config['vmq_rest_port']

def get_log_file():
    global g_config
    return g_config['log_file']

def get_app_logger():
    global g_config
    return g_config['logger']

def get_kconnect_path():
    global g_config
    return g_config['kconnect_path']

def get_kconnect_cert_path():
    global g_config
    return g_config['kconnect_cert_path']

def get_kconnect_config():
    global g_config
    return g_config['kconnect_config']

def get_kconnect_kc_url():
    global g_config
    return g_config['kconnect_kc_url']

def get_kconnect_kafka_topic():
    global g_config
    return g_config['kconnect_kafka_topic']

def update_kconnect_config(name, kconfig, action = 'CREATE'):
    global g_config
    
    if action == 'CREATE':
        g_config['kconnect_config'][name] = kconfig
        fp = open(get_kconnect_path() + name, 'w')
        fp.write(json.dumps(kconfig))
        fp.close()
    elif action == 'DELETE':
        os.remove(get_kconnect_path() + name)
        del get_kconnect_config()[name]
        
def get_kconnect_sync_thrid():
    global g_config
    return g_config['kconnect_sync_thread'] 
