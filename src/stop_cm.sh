ps -ef | grep 'python main.py' | awk {'print $2'} | xargs sudo kill -9
echo 'cm manager stopped'

