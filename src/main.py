"""
Entry File for connection Manager
"""
import sys
import appconfig
import rest

####### COMMON UTILITY FUNCTIONS ########



def log_event(ev_str):
    """
    Logs event string in log file
    """
    print ev_str
    pass
    return 
    
def init_config(file_name, mod_name):
    appconfig.set_app_module(mod_name)
    appconfig.init_appconfig(file_name)
    rest.init_rest()
    

def main():
    
    global g_config
    if len (sys.argv) != 2:
        print "Usage: python main.py <web|mqtt|kconnect>"
        sys.exit(1)   
    
    config_file = 'config.json'
    init_config(config_file, sys.argv[1])
    appconfig.get_kconnect_sync_thrid().start()
    rest.start_rest_mod()
    
    appconfig.get_kconnect_sync_thrid().join() 
    
if __name__ == '__main__':
    main()
