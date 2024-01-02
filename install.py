#!/usr/bin/python3
# -*- coding: utf-8 -*-
import subprocess, os, random, string, sys, shutil, socket, zipfile, urllib.request, urllib.error, urllib.parse, json, base64
from itertools import cycle
from zipfile import ZipFile
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from itertools import cycle, izip


rDownloadURL = {"main": "https://www.dropbox.com/s/evmuke4nci5fxra/main.tar.gz?dl=0", "sub": "https://www.dropbox.com/s/s515bykh6g3kwyq/sub.tar.gz?dl=0"}
rPackages = ["libcurl4", "libxslt1-dev", "libgeoip-dev", "libgeoip-dev", "libxslt1-dev", "e2fsprogs", "wget", "mcrypt", "nscd", "htop", "zip", "unzip", "mc", "mariadb-common", "mariadb-server", "libpng16-16", "libzip5", "python3-paramiko", "python-is-python3"]
rInstall = {"MAIN": "main", "LB": "sub"}
rUpdate = {"ADMIN": "admin"}
rMySQLCnf = "IyBYdHJlYW0gQ29kZXMKCltjbGllbnRdCnBvcnQgICAgICAgICAgICA9IDMzMDYKCltteXNxbGRfc2FmZV0KbmljZSAgICAgICAgICAgID0gMAoKW215c3FsZF0KdXNlciAgICAgICAgICAgID0gbXlzcWwKcG9ydCAgICAgICAgICAgID0gNzk5OQpiYXNlZGlyICAgICAgICAgPSAvdXNyCmRhdGFkaXIgICAgICAgICA9IC92YXIvbGliL215c3FsCnRtcGRpciAgICAgICAgICA9IC90bXAKbGMtbWVzc2FnZXMtZGlyID0gL3Vzci9zaGFyZS9teXNxbApza2lwLWV4dGVybmFsLWxvY2tpbmcKc2tpcC1uYW1lLXJlc29sdmU9MQoKYmluZC1hZGRyZXNzICAgICAgICAgICAgPSAqCmtleV9idWZmZXJfc2l6ZSA9IDEyOE0KCm15aXNhbV9zb3J0X2J1ZmZlcl9zaXplID0gNE0KbWF4X2FsbG93ZWRfcGFja2V0ICAgICAgPSA2NE0KbXlpc2FtLXJlY292ZXItb3B0aW9ucyA9IEJBQ0tVUAptYXhfbGVuZ3RoX2Zvcl9zb3J0X2RhdGEgPSA4MTkyCnF1ZXJ5X2NhY2hlX2xpbWl0ICAgICAgID0gNE0KcXVlcnlfY2FjaGVfc2l6ZSAgICAgICAgPSAyNTZNCgoKZXhwaXJlX2xvZ3NfZGF5cyAgICAgICAgPSAxMAptYXhfYmlubG9nX3NpemUgICAgICAgICA9IDEwME0KCm1heF9jb25uZWN0aW9ucyAgPSAyMDAwMApiYWNrX2xvZyA9IDQwOTYKb3Blbl9maWxlc19saW1pdCA9IDIwMjQwCmlubm9kYl9vcGVuX2ZpbGVzID0gMjAyNDAKbWF4X2Nvbm5lY3RfZXJyb3JzID0gMzA3Mgp0YWJsZV9vcGVuX2NhY2hlID0gNDA5Ngp0YWJsZV9kZWZpbml0aW9uX2NhY2hlID0gNDA5NgoKCnRtcF90YWJsZV9zaXplID0gMUcKbWF4X2hlYXBfdGFibGVfc2l6ZSA9IDFHCgppbm5vZGJfYnVmZmVyX3Bvb2xfc2l6ZSA9IDEwRwppbm5vZGJfYnVmZmVyX3Bvb2xfaW5zdGFuY2VzID0gMTAKaW5ub2RiX3JlYWRfaW9fdGhyZWFkcyA9IDY0Cmlubm9kYl93cml0ZV9pb190aHJlYWRzID0gNjQKaW5ub2RiX3RocmVhZF9jb25jdXJyZW5jeSA9IDAKaW5ub2RiX2ZsdXNoX2xvZ19hdF90cnhfY29tbWl0ID0gMAppbm5vZGJfZmx1c2hfbWV0aG9kID0gT19ESVJFQ1QKcGVyZm9ybWFuY2Vfc2NoZW1hID0gMAppbm5vZGItZmlsZS1wZXItdGFibGUgPSAxCmlubm9kYl9pb19jYXBhY2l0eT0yMDAwMAppbm5vZGJfdGFibGVfbG9ja3MgPSAwCmlubm9kYl9sb2NrX3dhaXRfdGltZW91dCA9IDAKaW5ub2RiX2RlYWRsb2NrX2RldGVjdCA9IDAKCgpzcWwtbW9kZT0iTk9fRU5HSU5FX1NVQlNUSVRVVElPTiIKCltteXNxbGR1bXBdCnF1aWNrCnF1b3RlLW5hbWVzCm1heF9hbGxvd2VkX3BhY2tldCAgICAgID0gMTZNCgpbbXlzcWxdCgpbaXNhbWNoa10Ka2V5X2J1ZmZlcl9zaXplICAgICAgICAgICAgICA9IDE2TQo=".decode("base64")

class col:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generate(length=16): return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def getIP():
    ip = urlopen('http://ip.42.pl/raw').read().decode()
    return ip


def getVersion():
    try: return subprocess.check_output("lsb_release -d".split()).split(":")[-1].strip()
    except: return ""

def printc(rText, rColour=col.OKBLUE, rPadding=0):
    print "%s ┌──────────────────────────────────────────┐ %s" % (rColour, col.ENDC)
    for i in range(rPadding): print "%s │                                          │ %s" % (rColour, col.ENDC)
    print "%s │ %s%s%s │ %s" % (rColour, " "*(20-(len(rText)/2)), rText, " "*(40-(20-(len(rText)/2))-len(rText)), col.ENDC)
    for i in range(rPadding): print "%s │                                          │ %s" % (rColour, col.ENDC)
    print "%s └──────────────────────────────────────────┘ %s" % (rColour, col.ENDC)
    print " "

def prepare(rType="MAIN"):
    global rPackages
    if rType != "MAIN": rPackages = rPackages[:-3]
    printc("Preparing Installation")
    for rFile in ["/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock", "/var/lib/dpkg/lock"]:
        try: os.remove(rFile)
        except: pass
    os.system("apt-get update > /dev/null")
    for rPackage in rPackages:
        printc("Installing %s" % rPackage)
        os.system("apt-get install %s -y > /dev/null" % rPackage)
    os.system("apt-get install -f > /dev/null") # Clean up above
    os.system("systemctl start mariadb")
    try:
        subprocess.check_output("getent passwd xtreamcodes > /dev/null".split())
    except:
        # Create User
        printc("Creating user xtreamcodes")
        os.system("adduser --system --shell /bin/false --group --disabled-login xtreamcodes > /dev/null")
    if not os.path.exists("/home/xtreamcodes"): os.mkdir("/home/xtreamcodes")
    return True

def install(rType="MAIN"):
    global rInstall, rDownloadURL
    printc("Downloading Software")
    try: rURL = rDownloadURL[rInstall[rType]]
    except:
        printc("Invalid download URL!", col.FAIL)
        return False
    os.system('wget -q -O "/tmp/xtreamcodes.tar.gz" "%s"' % rURL)
    if os.path.exists("/tmp/xtreamcodes.tar.gz"):
        printc("Installing Software")
        os.system('tar -zxvf "/tmp/xtreamcodes.tar.gz" -C "/home/xtreamcodes/" > /dev/null')
        try: os.remove("/tmp/xtreamcodes.tar.gz")
        except: pass
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def mysql(rUsername, rPassword):
    global rMySQLCnf
    printc("Configuring MySQL")
    rCreate = True
    if os.path.exists("/etc/mysql/my.cnf"):
        if open("/etc/mysql/my.cnf", "r").read(14) == "# Xtream Codes": rCreate = False
    if rCreate:
        shutil.copy("/etc/mysql/my.cnf", "/etc/mysql/my.cnf.xc")
        rFile = open("/etc/mysql/my.cnf", "wb")
        rFile.write(rMySQLCnf)
        rFile.close()   
        os.system("systemctl restart mariadb > /dev/null")
    #printc("Enter MySQL Root Password:", col.WARNING)
    for i in range(5):
        rMySQLRoot = "" #raw_input("  ")
        print(" ")
        if len(rMySQLRoot) > 0: rExtra = " -p%s" % rMySQLRoot
        else: rExtra = ""
        printc("Drop existing & create database? Y/N", col.WARNING)
        if input("  ").upper() == "Y": rDrop = True
        else: rDrop = False
        try:
            if rDrop:
                os.system('rm -f /home/xtreamcodes/iptv_xtream_codes/config > /dev/null' )
                os.system('mysql -u root%s -e "DROP DATABASE IF EXISTS xtream_iptvpro; CREATE DATABASE IF NOT EXISTS xtream_iptvpro;" > /dev/null' % rExtra)
                os.system('mysql -u root%s -e "USE xtream_iptvpro; DROP USER IF EXISTS \'%s\'@\'%%\';" ' % (rExtra, rUsername))
                os.system("mysql -u root%s xtream_iptvpro < /home/xtreamcodes/iptv_xtream_codes/database.sql > /dev/null" % rExtra)
                os.system('mysql -u root%s -e "USE xtream_iptvpro; UPDATE settings SET live_streaming_pass = \'%s\', unique_id = \'%s\', crypt_load_balancing = \'%s\';" > /dev/null' % (rExtra, generate(20), generate(10), generate(20)))
                os.system('mysql -u root%s -e "USE xtream_iptvpro; REPLACE INTO streaming_servers (id, server_name, domain_name, server_ip, vpn_ip, ssh_password, ssh_port, diff_time_main, http_broadcast_port, total_clients, system_os, network_interface, latency, status, enable_geoip, geoip_countries, last_check_ago, can_delete, server_hardware, total_services, persistent_connections, rtmp_port, geoip_type, isp_names, isp_type, enable_isp, boost_fpm, http_ports_add, network_guaranteed_speed, https_broadcast_port, https_ports_add, whitelist_ips, watchdog_data, timeshift_only) VALUES (1, \'Main Server\', \'\', \'%s\', \'\', NULL, NULL, 0, 25461, 1000, \'%s\', \'eth0\', 0, 1, 0, \'\', 0, 0, \'{}\', 3, 0, 25462, \'low_priority\', \'\', \'low_priority\', 0, 1, \'\', 1000, 25463, \'\', \'[\"127.0.0.1\",\"%s\",\"%s\"]\', \'{}\', 0);" > /dev/null' % (rExtra, getLanIP(), getVersion(), getLanIP(), getIP()))
                os.system('mysql -u root%s -e "USE xtream_iptvpro; REPLACE INTO reg_users (id, username, password, email, member_group_id, verified, status) VALUES (1, \'admin\', \'\$6\$rounds=20000\$xtreamcodes\$XThC5OwfuS0YwS4ahiifzF14vkGbGsFF1w7ETL4sRRC5sOrAWCjWvQJDromZUQoQuwbAXAFdX3h3Cp3vqulpS0\', \'admin@website.com\', 1, 1, 1);" > /dev/null'  % rExtra)
                os.system('mysql -u root%s -e "CREATE USER \'%s\'@\'%%\' IDENTIFIED BY \'%s\'; GRANT ALL PRIVILEGES ON xtream_iptvpro.* TO \'%s\'@\'%%\' WITH GRANT OPTION; GRANT SELECT, LOCK TABLES ON xtream_iptvpro.* TO \'%s\'@\'%%\'; FLUSH PRIVILEGES;"' % (rExtra, rUsername, rPassword, rUsername, rUsername))
            os.system('mysql -u root%s -e "USE xtream_iptvpro; CREATE TABLE IF NOT EXISTS dashboard_statistics (id int(11) NOT NULL AUTO_INCREMENT, type varchar(16) NOT NULL DEFAULT \'\', time int(16) NOT NULL DEFAULT \'0\', count int(16) NOT NULL DEFAULT \'0\', PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=latin1; INSERT INTO dashboard_statistics (type, time, count) VALUES(\'conns\', UNIX_TIMESTAMP(), 0),(\'users\', UNIX_TIMESTAMP(), 0);\" > /dev/null' % rExtra)
            try: os.remove("/home/xtreamcodes/iptv_xtream_codes/database.sql")
            except: pass
            return True
        except: printc("Invalid password! Try again", col.FAIL)
    return False

def encrypt(rHost="127.0.0.1", rUsername="user_iptvpro", rPassword="", rDatabase="xtream_iptvpro", rServerID=1, rPort=7999):
    if os.path.isfile('/home/xtreamcodes/iptv_xtream_codes/config'):
        rDecrypt = decrypt()
        rHost = rDecrypt["host"]
        rPassword = rDecrypt["db_pass"]
        rServerID = int(rDecrypt["server_id"])
        rUsername = rDecrypt["db_user"]
        rDatabase = rDecrypt["db_name"]
        rPort = int(rDecrypt["db_port"])
    printc("Encrypting...")
    try: os.remove("/home/xtreamcodes/iptv_xtream_codes/config")
    except: pass
    rf = open('/home/xtreamcodes/iptv_xtream_codes/config', 'wb')
    lestring=''.join(chr(ord(c)^ord(k)) for c,k in zip('{\"host\":\"%s\",\"db_user\":\"%s\",\"db_pass\":\"%s\",\"db_name\":\"%s\",\"server_id\":\"%d\", \"db_port\":\"%d\"}' % (rHost, rUsername, rPassword, rDatabase, rServerID, rPort), cycle('5709650b0d7806074842c6de575025b1')))
    rf.write(base64.b64encode(bytes(lestring, 'ascii')))
    rf.close()
def decrypt():
    rConfigPath = "/home/xtreamcodes/iptv_xtream_codes/config"
    try: return json.loads(''.join(chr(c^ord(k)) for c,k in zip(base64.b64decode(open(rConfigPath, 'rb').read()), cycle('5709650b0d7806074842c6de575025b1'))))
    except: return None

def configure():
    printc("Configuring System")
    if not "/home/xtreamcodes/iptv_xtream_codes/" in open("/etc/fstab").read():
        rFile = open("/etc/fstab", "a")
        rFile.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0\ntmpfs /home/xtreamcodes/iptv_xtream_codes/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G 0 0")
        rFile.close()
    if not "xtreamcodes" in open("/etc/sudoers").read():
        os.system('echo "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr, /usr/bin/python2, /usr/bin/python" >> /etc/sudoers')

    try:
        os.remove("/usr/bin/ffmpeg")
    except:
        pass

    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/tv_archive"):
        os.mkdir("/home/xtreamcodes/iptv_xtream_codes/tv_archive/")
    os.system("ln -s /home/xtreamcodes/iptv_xtream_codes/bin/ffmpeg /usr/bin/")
    os.system("chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("wget -q https://bitbucket.org/le_lio/assets/raw/master/GeoLite2.mmdb -O /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb")
    os.system("wget -q https://bitbucket.org/le_lio/assets/raw/master/pid_monitor.php -O /home/xtreamcodes/iptv_xtream_codes/crons/pid_monitor.php")
    os.system("chown xtreamcodes:xtreamcodes -R /home/xtreamcodes > /dev/null")
    os.system("chmod -R 0777 /home/xtreamcodes > /dev/null")
    os.system("chattr +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("sed -i 's|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes 2>/dev/null|g' /home/xtreamcodes/iptv_xtream_codes/start_services.sh")
    os.system("chmod +x /home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")
    os.system("mount -a")
    os.system("chmod 0700 /home/xtreamcodes/iptv_xtream_codes/config > /dev/null")
    os.system("sed -i 's|echo \"Xtream Codes Reborn\";|header(\"Location: https://www.google.com/\");|g' /home/xtreamcodes/iptv_xtream_codes/wwwdir/index.php")

    if not "api.xtream-codes.com" in open("/etc/hosts").read():
        os.system('echo "127.0.0.1    api.xtream-codes.com" >> /etc/hosts')

    if not "downloads.xtream-codes.com" in open("/etc/hosts").read():
        os.system('echo "127.0.0.1    downloads.xtream-codes.com" >> /etc/hosts')

    if not "xtream-codes.com" in open("/etc/hosts").read():
        os.system('echo "127.0.0.1    xtream-codes.com" >> /etc/hosts')

    # Deploy systemd_start.sh
    start_script = """#!/bin/bash
    sudo -u xtreamcodes /home/xtreamcodes/iptv_xtream_codes/php/bin/php /home/xtreamcodes/iptv_xtream_codes/crons/setup_cache.php
    sudo -u xtreamcodes /home/xtreamcodes/iptv_xtream_codes/php/bin/php /home/xtreamcodes/iptv_xtream_codes/tools/signal_receiver.php >/dev/null 2>/dev/null &
    sudo -u xtreamcodes /home/xtreamcodes/iptv_xtream_codes/php/bin/php /home/xtreamcodes/iptv_xtream_codes/tools/pipe_reader.php >/dev/null 2>/dev/null &
    chown -R xtreamcodes:xtreamcodes /sys/class/net
    chown -R xtreamcodes:xtreamcodes /home/xtreamcodes 2>/dev/null
    /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp
    /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx
    /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --daemonize --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/VaiIb8.conf
    /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --daemonize --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/JdlJXm.conf
    /home/xtreamcodes/iptv_xtream_codes/php/sbin/php-fpm --daemonize --fpm-config /home/xtreamcodes/iptv_xtream_codes/php/etc/CWcfSP.conf
    """
    with open('/home/xtreamcodes/iptv_xtream_codes/systemd_start.sh', 'w') as start_file:
        start_file.write(start_script)

    # Deploy systemd_stop.sh
    stop_script = """#!/bin/bash
    kill $(ps aux | grep 'xtreamc' | grep -v grep | grep -v 'start_services.sh' | awk '{print $2}') 2>/dev/null
    sleep 1
    kill $(ps aux | grep 'xtreamc' | grep -v grep | grep -v 'start_services.sh' | awk '{print $2}') 2>/dev/null
    sleep 1
    kill $(ps aux | grep 'xtreamc' | grep -v grep | grep -v 'start_services.sh' | awk '{print $2}') 2>/dev/null
    """
    with open('/home/xtreamcodes/iptv_xtream_codes/systemd_stop.sh', 'w') as stop_file:
        stop_file.write(stop_script)

    # Deploy xtreamui-22.service
    service_unit = """[Unit]
    Description=XtreamUI Main 20.04 NeySlim Edition
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=forking
    ExecStart=/home/xtreamcodes/iptv_xtream_codes/systemd_start.sh
    ExecStop=/home/xtreamcodes/iptv_xtream_codes/systemd_stop.sh
    TimeoutSec=0
    RemainAfterExit=yes
    GuessMainPID=no

    [Install]
    WantedBy=multi-user.target
    """
    with open('/etc/systemd/system/xtreamui.service', 'w') as service_file:
        service_file.write(service_unit)

    os.system('chown xtreamcodes. /home/xtreamcodes/iptv_xtream_codes/systemd_st*')
    os.system('chmod +x /home/xtreamcodes/iptv_xtream_codes/systemd_st*')
    os.system('systemctl daemon-reload')
    os.system('systemctl enable xtreamui.service')

def start(first=True):
    if first: printc("Starting Xtream Codes")
    else: printc("Restarting Xtream Codes")
    os.system("/home/xtreamcodes/iptv_xtream_codes/systemd_stop.sh")
    os.system("systemctl restart xtreamui")

def modifyNginx():
    printc("Modifying Nginx")
    rPath = "/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf"
    rPrevData = open(rPath, "r").read()
    if not "listen 25500;" in rPrevData:
        shutil.copy(rPath, "%s.xc" % rPath)
        rData = "}".join(rPrevData.split("}")[:-1]) + "    server {\n        listen 25500;\n        index index.php index.html index.htm;\n        root /home/xtreamcodes/iptv_xtream_codes/admin/;\n\n        location ~ \.php$ {\n                    limit_req zone=one burst=8;\n            try_files $uri =404;\n                    fastcgi_index index.php;\n                      fastcgi_pass php;\n                     include fastcgi_params;\n                       fastcgi_buffering on;\n                 fastcgi_buffers 96 32k;\n                       fastcgi_buffer_size 32k;\n                fastcgi_max_temp_file_size 0;\n                  fastcgi_keep_conn on;\n                 fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n                     fastcgi_param SCRIPT_NAME $fastcgi_script_name;\n        }\n    }\n}"
        rFile = open(rPath, "w")
        rFile.write(rData)
        rFile.close()

if __name__ == "__main__":
    printc("XtreamUI 20.04 Installer - NeySlim Edition", col.OKGREEN, 2)
    print(" ")
    rType = "MAIN"
    print(" ")
    if rType.upper() in ["MAIN", "LB"]:
        rHost = "127.0.0.1"
        rPassword = generate()
        rServerID = 1
        rUsername = "user_iptvpro"
        rDatabase = "xtream_iptvpro"
        rPort = 7999
        if len(rHost) > 0 and len(rPassword) > 0 and rServerID > -1:
            printc("Start installation? Y/N", col.WARNING)
            if input("  ").upper() == "Y":
                print(" ")
                rRet = prepare(rType.upper())
                if not install(rType.upper()): sys.exit(1)
                if rType.upper() == "MAIN":
                    if not mysql(rUsername, rPassword): sys.exit(1)
                encrypt(rHost, rUsername, rPassword, rDatabase, rServerID, rPort)
                configure()
                if rType.upper() == "MAIN": modifyNginx()
                start()
                printc("Installation completed!", col.OKGREEN, 2)
                printc("Admin UI: http://%s:25500" % getIP())
                if rType.upper() == "MAIN":
                    printc("Please store your MySQL password!")
                    printc(rPassword)
                    printc("Admin UI Wan IP: http://%s:25500" % getIP())
                    printc("Admin UI Lan IP: http://%s:25500" % getLanIP())
                    printc("Admin UI default login is admin/admin")
            else: printc("Installation cancelled", col.FAIL)
        else: printc("Invalid entries", col.FAIL)
    
