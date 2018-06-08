#import operator
#import unittest

#from mockio import mockio

from nginxparser import NginxParser, load,  dumps


def test_issue():
    #print 'hi'
    config = load(open('../stream.conf'))
    
    print config[0]
    print config[1]
    print config[2]
    
    #str_config = dumps(config[2])
    
    print dumps([[['server'], [
            ['listen', '80'],
            ['server_name', 'foo.com'],
            ['root', '/home/ubuntu/sites/foo/']]]
                 ])
    """
    print dumps([
            ['user', 'www-data'],
            [['server'], [
                ['listen', '80'],
                ['server_name', 'foo.com'],
                ['root', '/home/ubuntu/sites/foo/'],
                [['location', '/status'], [
                    ['check_status'],
                    [['types'], [['image/jpeg', 'jpg']]],
                ]]
            ]]])
    """
    #print str_config
    

if __name__ == '__main__':
    test_issue()
 #   unittest.main()
