#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib2, base64, re, struct, time, socket, sys, datetime, os.path

try:
    import json
except:
    import simplejson as json

zabbix_host = '127.0.0.1'   # Zabbix server IP
zabbix_port = 10051         # Zabbix server port
hostname = 'Zabbix Agent'   # Name of monitored host, like it shows in zabbix web ui
time_delta = 1              # grep interval in minutes

# Nginx log file path
nginx_log_file_path = '/data/logs/nginx/'
nginx_log_file = ['access.log']

# Directory with log file cursor position
seek_file_path = 'seek'

class Metric(object):
    def __init__(self, host, key, value, clock=None):
        self.host = host
        self.key = key
        self.value = value
        self.clock = clock

    def __repr__(self):
        if self.clock is None:
            return 'Metric(%r, %r, %r)' % (self.host, self.key, self.value)
        return 'Metric(%r, %r, %r, %r)' % (self.host, self.key, self.value, self.clock)

def send_to_zabbix(metrics, zabbix_host='127.0.0.1', zabbix_port=10051):
    j = json.dumps
    metrics_data = []
    for m in metrics:
        clock = m.clock or ('%d' % time.time())
        metrics_data.append(('{"host":%s,"key":%s,"value":%s,"clock":%s}') % (j(m.host), j(m.key), j(m.value), j(clock)))
    json_data = ('{"request":"sender data","data":[%s]}') % (','.join(metrics_data))
    data_len = struct.pack('<Q', len(json_data))
    packet = 'ZBXD\x01'+ data_len + json_data

    #print packet
    #print ':'.join(x.encode('hex') for x in packet)

    try:
        zabbix = socket.socket()
        zabbix.connect((zabbix_host, zabbix_port))
        zabbix.sendall(packet)
        resp_hdr = _recv_all(zabbix, 13)
        if not resp_hdr.startswith('ZBXD\x01') or len(resp_hdr) != 13:
            print 'Wrong zabbix response'
            return False
        resp_body_len = struct.unpack('<Q', resp_hdr[5:])[0]
        resp_body = zabbix.recv(resp_body_len)
        zabbix.close()

        resp = json.loads(resp_body)
        #print resp
        if resp.get('response') != 'success':
            print 'Got error from Zabbix: %s' % resp
            return False
        return True
    except:
        print 'Error while sending data to Zabbix'
        return False


def _recv_all(sock, count):
    buf = ''
    while len(buf)<count:
        chunk = sock.recv(count-len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf

def read_seek(file):
    if os.path.isfile(file):
        f = open(file, 'r')
        try:
            result = (int(x) for x in f.readline().split(','))
            f.close()
            return result
        except:
            return 0,0,0
    else:
        return 0,0,0

def write_seek(file, seek, timetag, ctime):
    f = open(file, 'w')
    value = ','.join(str(x) for x in (seek, int(timetag), int(ctime)))
    f.write(value)
    f.close()

for logname in nginx_log_file:
    seek_file = os.path.join(seek_file_path, logname)
    seek, timetag, ctime = read_seek(seek_file)

    logfile = os.path.join(nginx_log_file_path, logname)
    nf = open(logfile, 'r')
    # if new log file, don't do seek
    logctime = int(os.path.getctime(logfile))
    if logctime == ctime:
        nf.seek(seek)

    end = datetime.datetime.now()-datetime.timedelta(minutes=1)
    end_minute = int(time.mktime(end.timetuple()) / 60)*60
    minutes = end_minute - timetag
    [(now-datetime.timedelta(minutes=x)).strftime('%d/%b/%Y:%H:%M') for x in range(5,0,-1)]
    timetag = pretime.strftime('%d/%b/%Y:%H:%M')

    line = nf.readline()
    while line:
        if d in line:
                new_seek = nf.tell()
                total_rps += 1
                sec = int(re.match('(.*):(\d+):(\d+):(\d+)\s', line).group(4))
                code = re.match(r'(.*)"\s(\d*)\s', line).group(2)
                if code in res_code:
                    res_code[code] += 1
                else:
                    res_code[code] = 1

                rps[sec] += 1
            line = nf.readline()

minute = int(time.mktime(pretime.timetuple()) / 60)*60
timetag = pretime.strftime('%d/%b/%Y:%H:%M')

total_rps = 0
rps = [0]*60

tps = [0]*60
res_code = {}

nf = open(nginx_log_file_path, 'r')

new_seek = seek = read_seek(seek_file)

# if new log file, don't do seek
if os.path.getsize(nginx_log_file_path) > seek:
    nf.seek(seek)

line = nf.readline()
while line:
    if d in line:
        new_seek = nf.tell()
        total_rps += 1
        sec = int(re.match('(.*):(\d+):(\d+):(\d+)\s', line).group(4))
        code = re.match(r'(.*)"\s(\d*)\s', line).group(2)
        if code in res_code:
            res_code[code] += 1
        else:
            res_code[code] = 1

        rps[sec] += 1
    line = nf.readline()

if total_rps != 0:
    write_seek(seek_file, str(new_seek))

nf.close()

metric = (len(sys.argv) >= 2) and re.match(r'nginx\[(.*)\]', sys.argv[1], re.M | re.I).group(1) or False
data = get(stat_url, username, password).split('\n')
data = parse_nginx_stat(data)

data_to_send = []

# Adding the metrics to response
if not metric:
    for i in data:
        data_to_send.append(Metric(hostname, ('nginx[%s]' % i), data[i]))
else:
    print data[metric]

# Adding the request per seconds to response
for t in range(0,60):
    data_to_send.append(Metric(hostname, 'nginx[rps]', rps[t], minute+t))

# Adding the response codes stats to respons
for t in res_code:
    data_to_send.append(Metric(hostname, ('nginx[%s]' % t), res_code[t]))


send_to_zabbix(data_to_send, zabbix_host, zabbix_port)
