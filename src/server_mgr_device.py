__author__ = 'jalandip'
from netaddr import *
from json import *
from jnpr.junos import Device
import jnpr
from time import localtime, strftime
from server_mgr_logger import ServerMgrlogger
import eventlet
import pycurl
from server_mgr_defaults import *
eventlet.monkey_patch(socket=True, thread=False)

class DeviceManager():

    def __init__(self, _vnc_ip='127.0.0.1',_vnc_port=9991):
        self._pool = eventlet.GreenPool()
        self._deviceList = {}
        self._smgr_log = ServerMgrlogger()
        self._vnc_ip = _vnc_ip
        self._vnc_port = _vnc_port

    # generator that returns list of ips
    def __generate_block_ip_list(self, ipList, blocksize):
        for i in xrange(0, len(ipList), blocksize):
            yield ipList[i:blocksize + i]


    def discover(self, discovery_data):
        self._smgr_log.log(self._smgr_log.WARN, "Start discover device ")
        subnet = None;ip_range=None; ip_list=None
        try:
            if discovery_data['device-discovery'] is not None:
                if 'ip-range' in discovery_data['device-discovery']:
                    ip_range = discovery_data['device-discovery']['ip-range']
                if 'subnet' in discovery_data['device-discovery']:
                    subnet = discovery_data['device-discovery']['subnet']
                if 'ip-list' in discovery_data['device-discovery']:
                    ip_list = discovery_data['device-discovery']['ip-list']

                credentials = discovery_data['device-discovery']['credentials']
                discover_host_list = self.__get_discover_ip_list(ip_range, subnet, ip_list)
                for ip_block in self.__generate_block_ip_list(discover_host_list, 10):
                    pile = eventlet.GreenPile(self._pool)
                    self._smgr_log.log(self._smgr_log.WARN, "Start processing " + str(ip_block))
                    pile.spawn(self.__get_devices_info,ip_block, credentials)
                for result in pile:
                    self._smgr_log.log(self._smgr_log.WARN,"Done")
        except Exception as e:
            self._smgr_log.log(self._smgr_log.ERROR, repr(e))
            raise e

    def __get_discover_ip_list(self, iprange = None, subnet = None, ip_list = None):
        all_ips = []
        if iprange is not None:
            encoded_ip_range = iprange.encode("utf-8")
            if "-" in encoded_ip_range.encode("utf-8"):
                (start, sep, finish) = encoded_ip_range.partition("-")
                all_ips.extend((iter_iprange(start, finish)))
        if subnet is not None:
            encoded_subnet = subnet.encode("utf-8")
            try:
                all_ips.extend((IPNetwork(encoded_subnet)))
            except Exception as e:
                self._smgr_log.log(self._smgr_log.ERROR,"Error in specification " )
                self._smgr_log.log(self._smgr_log.ERROR,repr(e))
        if ip_list is not None:
            for ip in ip_list:
                all_ips.append(IPAddress(ip['ip'].encode("utf-8")))
        return all_ips

    @staticmethod
    def __timestr():
        return strftime(" (%Y-%m-%d %H:%M:%S)", localtime())


    def __get_devices_info(self, ip_blocks, credentials):
        self._smgr_log.log(self._smgr_log.WARN, "Start get_device_info for " + str(ip_blocks))
        for ip in ip_blocks:
            device_ip = str(ip)
            if device_ip not in self._deviceList:
                for credential in credentials:
                    username=credential['user'].encode("utf-8")
                    password=credential['password'].encode("utf-8")
                    jdev = Device(user=username, host=device_ip, password=password)
                    self._smgr_log.log(self._smgr_log.WARN,self.__timestr() + ": Start on device %s, with user %s with pass %s" % (device_ip,username,password))
                    try:
                        if jdev.probe(timeout=2) is True:
                            jdev.open()
                            facts = jdev.facts
                            self._smgr_log.log(self._smgr_log.WARN,"Done processing device with ip %s, facts %s " % (str(ip), facts))
                            self.__send_REST_request(DeviceManager.__to_device_data(facts,device_ip))
                        else:
                            self._smgr_log.log(self._smgr_log.WARN, "Device %s is not reachable" % device_ip)
                            break
                    except Exception as e:
                        self._smgr_log.log(self._smgr_log.WARN, "Failed device discovery")
                        self._smgr_log.log(self._smgr_log.WARN, repr(e))
                        #try with next credential
                        continue
                    break


    @staticmethod
    def __to_device_data(facts=None, device_ip=""):
        if facts is None:
            return None
        device_data = {}
        for k,v in device_fields.iteritems():
            if k in facts:
                device_data[k] = str(facts[k])
            else:
                device_data[k] = device_fields[k]
        device_data['ip'] = device_ip
        return device_data

    def getDevices(self):
        return DeviceEncoder(indent=4).encode(self._deviceList.values())

    def __send_REST_request(self, payload):
        try:
            url = "http://%s:%s/add_device" % (self._vnc_ip, self._vnc_port)
            json_payload = DeviceEncoder().encode(payload)
            self._smgr_log.log(self._smgr_log.ERROR, "Sending REST Request to %s : %s " % (url, json_payload))
            headers = ["Content-Type:application/json"]
            conn = pycurl.Curl()
            conn.setopt(pycurl.TIMEOUT, 30)
            conn.setopt(pycurl.URL, url)
            conn.setopt(pycurl.HTTPHEADER, headers)
            conn.setopt(pycurl.POST, 1)
            conn.setopt(pycurl.POSTFIELDS, json_payload)
            conn.perform()
        except Exception as e:
            self._smgr_log.log(self._smgr_log.ERROR, "Failed to add device %s to DB " % payload['ip'])
            self._smgr_log.log(self._smgr_log.ERROR,repr(e))
            return

class DeviceEncoder(JSONEncoder):
    def default(self, o):
       try:
         if type(o) is jnpr.junos.facts.swver.version_info:
            return str(o)
       except TypeError:
           pass
       else:
           return "Unknown"
       # Let the base class default method raise the TypeError
       return JSONEncoder.default(self, o)


