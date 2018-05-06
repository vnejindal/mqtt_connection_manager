"""

Config file handling

"""
import json
import re
import os

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
        load_nginx_params()
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
    
    g_config['kconnect_path'] = cpath
    # KC REST URL ; Hardcoding it as it will sit on same machine
    g_config['kconnect_kc_url'] = '127.0.0.1:8083'
    g_config['kconnect_config'] = {}
    
    for filename in os.listdir(get_kconnect_path()):
        fp = open(filename, 'r')
        get_kconnect_config()[filename] = json.loads(fp.read())
        fp.close()
   
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
        #vne:: tbd:: add support for multiple vermq servers     
    
           
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

def get_kconnect_config():
    global g_config
    return g_config['kconnect_config']

def get_kconnect_kc_url():
    global g_config
    return g_config['kconnect_kc_url']

def get_kconnect_kafka_topic():
    global g_config
    return g_config['kconnect_kafka_topic']

def update_kconnect_config(name, kconfig):
    global g_config
    
    g_config['kconnect_config'][name] = kconfig
    
    fname = get_kconnect_path() + name    
    fp = open(fname, 'w')
    fp.write(json.dumps(kconfig))
    fp.close()
    
