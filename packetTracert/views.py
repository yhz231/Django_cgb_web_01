from datetime import datetime
import re
import uuid
from django.core.cache import cache

from packetTracert.ccp_util import IPv4Obj
from packetTracert.models import TimeRange, Policy, ObjectPolicy, AccessGroup
from packetTracert.protocol_values import ASA_TCP_PORTS, ASA_UDP_PORTS, ASA_IP_PROTOCOLS
from django.shortcuts import render

# Create your views here.


class SolveRules:
    def __init__(self, firewall=None, file=None):
        reslist = []
        lines = file.readlines().__len__()
        file.seek(0)
        for i in range(lines):
            a = re.search('(access-list\s[^&]*)', file.readline().rstrip('\n'))
            if a is not None:
                reslist.append(a.group(0).lstrip())
        self.reslist = reslist
        self.firewall_name = firewall

    def write_database(self, acl_db=None, obj_db=None):
        for i in self.reslist:
            res = ASAAclLine(i).result_dict()
            acl_name_val = res['acl_name']
            if AccessGroup.objects.filter(access_group=acl_name_val, firewall_name=self.firewall_name):
                interface_val = res['interface']
                original_acl_val = ASAAclLine(i)._original_acl
                line_no_val = res['line_no']
                protocol_val = res['ip_protocol']
                src_ip_val = res['src_addr_network']
                src_mask_val = res['src_addr_mask']
                src_port_low_val = res['src_port_low']
                src_port_high_val = res['src_port_high']
                dst_ip_val = res['dst_addr_network']
                dst_mask_val = res['dst_addr_mask']
                dst_port_low_val = res['dst_port_low']
                dst_port_high_val = res['dst_port_high']
                action_val = res['action']
                time_range_val = res['time_range']
                hitcnt_val = res['hitcnt']
                acl_id_val = res['acl_id']
                if res['port_object'] or res['ip_protocol_object'] or (res['src_addr_method'] in ['object', 'object-group'])\
                        or (res['dst_addr_method'] in ['object', 'object-group']):
                    has_objectgroup = True
                else:
                    has_objectgroup = False
                if has_objectgroup:
                    uuid_val = uuid.uuid1()
                    cache.set('line_no', line_no_val)
                    cache.set('interface', interface_val)
                    cache.set('uuid', uuid_val)
                    try:
                        object = obj_db(original_acl=original_acl_val, uuid=uuid_val)
                        object.save()
                    except:
                        raise ValueError("Cannot write object_database for '{0}'".format(i))
                else:
                    line_no_previous = cache.get('line_no')
                    interface_previous = cache.get('interface')
                    uuid_previous = cache.get('uuid')
                    if (line_no_previous, interface_previous) == (line_no_val, interface_val):
                        uuid_val = uuid_previous
                        has_objectgroup = True
                    else:
                        uuid_val = uuid.uuid1()
                        has_objectgroup = False
                    try:
                        acl = acl_db(firewall_name=self.firewall_name, original_acl=original_acl_val, line_no=line_no_val, protocol=protocol_val, interface=interface_val, src_ip=src_ip_val, src_mask=src_mask_val, src_port_low=src_port_low_val, src_port_high=src_port_high_val, dst_ip=dst_ip_val, dst_mask=dst_mask_val, dst_port_low=dst_port_low_val, dst_port_high=dst_port_high_val, action=action_val, time_range=time_range_val, hitcnt=hitcnt_val, uuid=uuid_val ,has_objectgroup=has_objectgroup)
                        acl.save()
                    except:
                        raise ValueError("Cannot write acl_database for '{0}'".format(i))



# solve acl policy to stander format
_ACL_PROTOCOLS = 'ip|tcp|udp|ah|eigrp|esp|gre|igmp|igrp|ipinip|ipsec|ospf|pcp|pim|pptp|snp|\d+'
_ACL_ICMP_PROTOCOLS = 'alternate-address|conversion-error|echo-reply|echo|information-reply|information-request|mask-reply|mask-request|mobile-redirect|parameter-problem|redirect|router-advertisement|router-solicitation|source-quench|time-exceeded|timestamp-reply|timestamp-request|traceroute|unreachable'
_ACL_LOGLEVELS = r'alerts|critical|debugging|emergencies|errors|informational|notifications|warnings|[0-7]'
_RE_ACLOBJECT_STR = r"""(?:                         # Non-capturing parenthesis
# remark
 (^access-list\s+(?P<acl_name0>\S+)\s+(?P<action0>remark)\s+(?P<remark>\S.+?)$)
# extended service object with source network object, destination network object
|(?:^access-list\s+(?P<acl_name1>\S+)
  \s+line\s+(?P<line_no1>\d+)\s+extended\s+(?P<action1>permit|deny)
  \s+(?:
     (?:object-group\s+(?P<service_object1>\S+))
    |(?P<protocol1>{0})
  )
  \s+(?:                       # 10.0.0.0 255.255.255.0
     (?:object-group\s+(?P<src_networkobject1>\S+))
    |(?:object\s+(?P<src_object1>\S+))
    |(?:(?P<src_network1a>\S+)\s+(?P<src_netmask1a>\d+\.\d+\.\d+\.\d+))
  )
  \s+(?:                       # 10.0.0.0 255.255.255.0
     (?:object-group\s+(?P<dst_networkobject1>\S+))
    |(?:object\s+(?P<dst_object1>\S+))
    |(?:(?P<dst_network1a>\S+)\s+(?P<dst_netmask1a>\d+\.\d+\.\d+\.\d+))
  )
  (?:\s+
    (?P<log1>log)
    (?:\s+(?P<loglevel1>{1}))?
    (?:\s+interval\s+(?P<log_interval1>\d+))?
  )?
  (?:\s+(?P<disable1>disable))?
  (?:
    (?:\s+(?P<inactive1>inactive))
   |(?:\s+time-range\s+(?P<time_range1>\S+))
  )?
 \s+\S+hitcnt=(?P<hitcnt1>\d+)\S+\s+(?P<acl_id1>0x\S+)
 $)    # END access-list 1 parse
# extended service object with source network, destination network
# access-list TESTME1 extended permit ip any any log
|(?:^access-list\s+(?P<acl_name2>\S+)
  \s+line\s+(?P<line_no2>\d+)\s+extended
  \s+(?P<action2>permit|deny)
  \s+(?:                       # service-object or protocol
     (?:object-group\s+(?P<service_object2>\S+))
    |(?P<protocol2>{0})
  )
  (?:\s+       # any, any4, host foo, object-group FOO or 10.0.0.0 255.255.255.0
     (?:
       (?P<src_network2a>any|any4)
      |(?:host\s+(?P<src_network2b>\S+))
      |(?:object\s+(?P<src_object2>\S+))
      |(?:object-group\s+(?P<src_networkobject2>\S+))
      |(?:(?P<src_network2c>\S+)\s+(?P<src_netmask2c>\d+\.\d+\.\d+\.\d+))
    )
  )
  (?:\s+
    (?:
       (?:(?P<src_port_operator>eq|neq|lt|gt)\s+(?P<src_port>\S+))
      |(?:range\s+(?P<src_port_low>\S+)\s+(?P<src_port_high>\S+))
      |(?:object-group\s+(?P<src_service_object>\S+))
    )
  )?
  (?:\s+       # any, any4, host foo, object-group FOO or 10.0.0.0 255.255.255.0
     (?:
       (?P<dst_network2a>any|any4)
      |(?:host\s+(?P<dst_network2b>\S+))
      |(?:object\s+(?P<dst_object2>\S+))
      |(?:object-group\s+(?P<dst_networkobject2>\S+))
      |(?:(?P<dst_network2c>\S+)\s+(?P<dst_netmask2c>\d+\.\d+\.\d+\.\d+))
    )
  )
  (?:\s+
    (?:
       (?:(?P<dst_port_operator>eq|neq|lt|gt)\s+(?P<dst_port>\S+))
      |(?:range\s+(?P<dst_port_low>\S+)\s+(?P<dst_port_high>\S+))
      |(?:object-group\s+(?P<dst_service_object>\S+))
    )
  )?
  (?:\s+
    (?P<log2>log)
    (?:\s+(?P<loglevel2>{1}))?
    (?:\s+interval\s+(?P<log_interval2>\d+))?
  )?
  (?:\s+(?P<disable2>disable))?
  (?:
    (?:\s+(?P<inactive2>inactive))
   |(?:\s+time-range\s+(?P<time_range2>\S+))
  )?
 \s+\S+hitcnt=(?P<hitcnt2>\d+)\S+\s+(?P<acl_id2>0x\S+)
 $)    # END access-list 2 parse
# access-list SPLIT_TUNNEL_NETS standard permit 192.0.2.0 255.255.255.0
|(?:^access-list\s+(?P<acl_name3>\S+)
  \s+line\s+(?P<line_no3>\d+)\s+standard
  \s+(?P<action3>permit|deny)
  \s+(?:
    (?P<dst_network3a>any|any4)
   |(?:host\s+(?P<dst_network3b>\S+))
   |(?:(?P<dst_network3c>\S+)\s+(?P<dst_netmask3c>\d+\.\d+\.\d+\.\d+))
  )
  \s+\S+hitcnt=(?P<hitcnt3>\d+)\S+\s+(?P<acl_id3>0x\S+)
  )
#access-list TESTME extended permit icmp any4 0.0.0.0 0.0.0.0 unreachable log interval 1
|(?:^access-list\s+(?P<acl_name4>\S+)
  \s+line\s+(?P<line_no4>\d+)\s+extended
  \s+(?P<action4>permit|deny)
  \s+(?P<protocol4>icmp)
  (?:\s+       # any, any4, host foo, object-group FOO or 10.0.0.0 255.255.255.0
     (?:
       (?P<src_network4a>any|any4)
      |(?:host\s+(?P<src_network4b>\S+))
      |(?:object\s+(?P<src_object4>\S+))
      |(?:object-group\s+(?P<src_networkobject4>\S+))
      |(?:(?P<src_network4c>\S+)\s+(?P<src_netmask4c>\d+\.\d+\.\d+\.\d+))
    )
  )
  (?:\s+       # any, any4, host foo, object-group FOO or 10.0.0.0 255.255.255.0
     (?:
       (?P<dst_network4a>any|any4)
      |(?:host\s+(?P<dst_network4b>\S+))
      |(?:object\s+(?P<dst_object4>\S+))
      |(?:object-group\s+(?P<dst_networkobject4>\S+))
      |(?:(?P<dst_network4c>\S+)\s+(?P<dst_netmask4c>\d+\.\d+\.\d+\.\d+))
    )
  )
  (?:\s+(?P<icmp_proto4>{2}|\d+))?
  (?:\s+
    (?P<log4>log)
    (?:\s+(?P<loglevel4>{1}))?
    (?:\s+interval\s+(?P<log_interval4>\d+))?
  )?
  (?:\s+(?P<disable4>disable))?
  (?:
    (?:\s+(?P<inactive4>inactive))
   |(?:\s+time-range\s+(?P<time_range4>\S+))
  )?
  )
  \s+\S+hitcnt=(?P<hitcnt4>\d+)\S+\s+(?P<acl_id4>0x\S+)
)                                                   # Close non-capture parens
""".format(_ACL_PROTOCOLS, _ACL_LOGLEVELS, _ACL_ICMP_PROTOCOLS)
_RE_ACLOBJECT = re.compile(_RE_ACLOBJECT_STR, re.VERBOSE)

class ASAAclLine:
    def __init__(self, policy):
        """Provide attributes on Cisco ASA Access-Lists"""
        mm = _RE_ACLOBJECT.search(policy)
        self.policy = policy
        if not (mm is None):
            self._mm_results = mm.groupdict()   # All regex match results
            self._original_acl = mm.group(0)
        else:
            raise ValueError("[FATAL] models_asa cannot parse '{0}'".format(self.policy))


    def is_object_for(cls, line="", re=re):
        #if _RE_ACLOBJECT.search(line):
        if 'access-list ' in line[0:13].lower():
            return True
        return False

    def solve_src_addr(self):
        mm_r = self._mm_results
        retval = {}
        if mm_r['src_network1a'] is not None:
            retval['network'] = mm_r['src_network1a']
            retval['netmask'] = mm_r['src_netmask1a']
        elif mm_r['src_network2a'] is not None:
            retval['network'] = '0.0.0.0'
            retval['netmask'] = '0.0.0.0'
        elif mm_r['src_network2b'] is not None:
            retval['network'] = mm_r['src_network2b']
            retval['netmask'] = '255.255.255.255'
        elif mm_r['src_network2c'] is not None:
            retval['network'] = mm_r['src_network2c']
            retval['netmask'] = mm_r['src_netmask2c']
        elif mm_r['src_network4a'] is not None:
            retval['network'] = '0.0.0.0'
            retval['netmask'] = '0.0.0.0'
        elif mm_r['src_network4b'] is not None:
            retval['network'] = mm_r['src_network4b']
            retval['netmask'] = '255.255.255.255'
        elif mm_r['src_network4c'] is not None:
            retval['network'] = mm_r['src_network4c']
            retval['netmask'] = mm_r['src_netmask4c']
        else:
            retval['network'] = '0.0.0.0'
            retval['netmask'] = '0.0.0.0'
        return retval

    def solve_dst_addr(self):
        mm_r = self._mm_results
        retval = {}
        if mm_r['dst_network1a'] is not None:
            retval['network'] = mm_r['dst_network1a']
            retval['netmask'] = mm_r['dst_netmask1a']
        elif mm_r['dst_network2a'] is not None:
            retval['network'] = '0.0.0.0'
            retval['netmask'] = '0.0.0.0'
        elif mm_r['dst_network2b'] is not None:
            retval['network'] = mm_r['dst_network2b']
            retval['netmask'] = '255.255.255.255'
        elif mm_r['dst_network2c'] is not None:
            retval['network'] = mm_r['dst_network2c']
            retval['netmask'] = mm_r['dst_netmask2c']
        elif mm_r['dst_network3a'] is not None:
            retval['network'] = '0.0.0.0'
            retval['netmask'] = '0.0.0.0'
        elif mm_r['dst_network3b'] is not None:
            retval['network'] = mm_r['dst_network3b']
            retval['netmask'] = '255.255.255.255'
        elif mm_r['dst_network3c'] is not None:
            retval['network'] = mm_r['dst_network3c']
            retval['netmask'] = mm_r['dst_netmask3c']
        elif mm_r['dst_network4a'] is not None:
            retval['network'] = '0.0.0.0'
            retval['netmask'] = '0.0.0.0'
        elif mm_r['dst_network4b'] is not None:
            retval['network'] = mm_r['dst_network4b']
            retval['netmask'] = '255.255.255.255'
        elif mm_r['dst_network4c'] is not None:
            retval['network'] = mm_r['dst_network4c']
            retval['netmask'] = mm_r['dst_netmask4c']
        else:
            retval['network'] = '0.0.0.0'
            retval['netmask'] = '0.0.0.0'
        return retval

    def src_addr_method(self):
        mm_r = self._mm_results
        if mm_r['action0'] and (mm_r['action0']=='remark'):
            # remarks return an empty string
            return ''
        elif mm_r['src_networkobject1'] or mm_r['src_networkobject2'] or mm_r['src_networkobject4']:
            return 'object-group'
        elif mm_r['src_object1'] or mm_r['src_object2'] or mm_r['src_object4']:
            return 'object'
        elif mm_r['src_network1a'] or mm_r['src_network2a'] \
            or mm_r['src_network2b'] or mm_r['src_network2c'] \
            or mm_r['src_network4a'] or mm_r['src_network4b'] \
            or mm_r['src_network4c']:
            return 'network'
        ## NOTE: I intended to match dst addrs here...

        elif mm_r['acl_name3']:
            ## Special case: standard ACLs match any src implicitly
            self._mm_results['src_network3'] = 'any4'
            return 'network'
        else:
            raise ValueError("Cannot parse ACL source address method for '{0}'".format(self.policy))


    def dst_addr_method(self):
        mm_r = self._mm_results
        if mm_r['action0'] and (mm_r['action0']=='remark'):
            # remarks return an empty string
            return ''
        elif mm_r['dst_networkobject1'] or mm_r['dst_networkobject2'] or mm_r['dst_networkobject4']:
            return 'object-group'
        elif mm_r['dst_object1'] or mm_r['dst_object2'] or mm_r['dst_object4']:
            return 'object'
        elif mm_r['dst_network1a'] or mm_r['dst_network2a'] \
            or mm_r['dst_network2b'] or mm_r['dst_network2c'] \
            or mm_r['dst_network4a'] or mm_r['dst_network4b'] \
            or mm_r['dst_network4c']:
            return 'network'
        elif mm_r['dst_network3a'] or mm_r['dst_network3b'] \
            or mm_r['dst_network3c']:
            return 'network'
        else:
            raise ValueError("Cannot parse ACL destination address method for '{0}'".format(self.policy))

    def solve_service_port(self, port_dict, port, port_low, port_high ):
        mm_r = self._mm_results
        retval = dict()
        if mm_r[port] is not None:
            service_port = mm_r[port]
            retval[port_low] = int(port_dict.get(service_port, service_port))
            retval[port_high] = int(port_dict.get(service_port, service_port))
        elif mm_r[port_low] is not None:
            service_port_low = mm_r[port_low]
            retval[port_low] = int(port_dict.get(service_port_low, service_port_low))
            service_port_high = mm_r[port_high]
            retval[port_high] = int(port_dict.get(service_port_high, service_port_high))
        else:
            retval[port_low] = 0
            retval[port_high] = 65535
        return retval


    def acl_protocol_dict(self):
        mm_r = self._mm_results
        retval = dict()

        if mm_r['remark']:
            # remarks get IP protocol -1
            retval['protocol'] = -1
            retval['protocol_object'] = ''
            retval['port_object'] = ''
            retval['src_port_low'] = 0
            retval['src_port_high'] = 65535
            retval['dst_port_low'] = 0
            retval['dst_port_high'] = 65535
            return retval
        elif mm_r['protocol1'] or mm_r['protocol2'] or mm_r['protocol4']:
            _proto = mm_r['protocol1'] or mm_r['protocol2'] or mm_r['protocol4'] or -1
            retval['protocol'] = int(ASA_IP_PROTOCOLS.get(_proto, _proto))
            retval['protocol_object'] = ''
            if _proto == 'udp':
                res_src = self.solve_service_port(ASA_UDP_PORTS, 'src_port', 'src_port_low', 'src_port_high')
                res_dst = self.solve_service_port(ASA_UDP_PORTS, 'dst_port', 'dst_port_low', 'dst_port_high')
                retval['src_port_low'] = res_src['src_port_low']
                retval['src_port_high'] = res_src['src_port_high']
                retval['dst_port_low'] = res_dst['dst_port_low']
                retval['dst_port_high'] = res_dst['dst_port_high']
            elif _proto == 'tcp':
                res_src = self.solve_service_port(ASA_TCP_PORTS, 'src_port', 'src_port_low', 'src_port_high')
                res_dst = self.solve_service_port(ASA_TCP_PORTS, 'dst_port', 'dst_port_low', 'dst_port_high')
                retval['src_port_low'] = res_src['src_port_low']
                retval['src_port_high'] = res_src['src_port_high']
                retval['dst_port_low'] = res_dst['dst_port_low']
                retval['dst_port_high'] = res_dst['dst_port_high']
            else:
                retval['src_port_low'] = 0
                retval['src_port_high'] = 65535
                retval['dst_port_low'] = 0
                retval['dst_port_high'] = 65535
            if mm_r['src_service_object'] or mm_r['dst_service_object']:
                retval['port_object'] = mm_r['src_service_object'] or mm_r['dst_service_object']
            else:
                retval['port_object'] = ''
            return retval
        elif mm_r['acl_name3']:
            # Special case for standard ASA ACLs
            _proto = 'ip'
            retval['protocol'] = int(ASA_IP_PROTOCOLS.get(_proto, _proto))
            retval['protocol_object'] = ''
            retval['src_port_low'] = 0
            retval['src_port_high'] = 65535
            retval['dst_port_low'] = 0
            retval['dst_port_high'] = 65535
            retval['port_object'] = ''
            return retval
        elif mm_r['service_object1'] or mm_r['service_object2']:
            # protocol service objects get a special protocol number
            retval['protocol'] = 65535
            retval['protocol_object'] = mm_r['service_object1'] \
                or mm_r['service_object2']
            retval['port_object'] = mm_r['service_object1'] \
                or mm_r['service_object2']
            retval['src_port_low'] = 0
            retval['src_port_high'] = 65535
            retval['dst_port_low'] = 0
            retval['dst_port_high'] = 65535

            return retval
        else:
            raise ValueError("Cannot parse ACL protocol value for '{0}'".format(self.policy))


    def result_dict(self):
        mm_r = self._mm_results
        retval = dict()
        proto_dict = self.acl_protocol_dict()
        retval['ip_protocol'] = proto_dict['protocol']
        retval['ip_protocol_object'] = proto_dict['protocol_object']
        retval['src_port_low'] = proto_dict['src_port_low']
        retval['src_port_high'] = proto_dict['src_port_high']
        retval['dst_port_low'] = proto_dict['dst_port_low']
        retval['dst_port_high'] = proto_dict['dst_port_high']
        retval['port_object'] = proto_dict['port_object']
        acl_name = mm_r['acl_name0'] or mm_r['acl_name1'] \
            or mm_r['acl_name2'] or mm_r['acl_name3'] or mm_r['acl_name4']
        retval['acl_name'] = acl_name
        retval['interface'] = re.search('([^\_]+)', acl_name).group(1)
        retval['action'] = mm_r['action0'] or mm_r['action1'] \
            or mm_r['action2'] or mm_r['action3'] or mm_r['action4']
        retval['remark'] = mm_r['remark']
        retval['src_addr_method'] = self.src_addr_method()
        retval['dst_addr_method'] = self.dst_addr_method()
        src_addr = self.solve_src_addr()
        dst_addr = self.solve_dst_addr()
        retval['src_addr_network'] = src_addr['network']
        retval['src_addr_mask'] = src_addr['netmask']
        retval['dst_addr_network'] = dst_addr['network']
        retval['dst_addr_mask'] = dst_addr['netmask']
        retval['disable'] = bool(mm_r['disable1'] or mm_r['disable2'] or mm_r['disable4'])
        retval['line_no'] = mm_r['line_no1'] or mm_r['line_no2'] or mm_r['line_no3'] or mm_r['line_no4']
        retval['hitcnt'] = mm_r['hitcnt1'] or mm_r['hitcnt2'] or mm_r['hitcnt3'] or mm_r['hitcnt4']
        retval['acl_id'] = mm_r['acl_id1'] or mm_r['acl_id2'] or mm_r['acl_id3'] or mm_r['acl_id4']
        if mm_r['time_range1'] or mm_r['time_range2'] or mm_r['time_range4']:
            retval['time_range'] = mm_r['time_range1'] or mm_r['time_range2'] or mm_r['time_range4']
        else:
            retval['time_range'] = ''
        retval['log'] = bool(mm_r['log1'] or mm_r['log2'] or mm_r['log4'])
        if not retval['log']:
            retval['log_interval'] = -1
            retval['log_level'] = ''
        else:
            retval['log_level'] = mm_r['loglevel1'] or mm_r['loglevel2'] or mm_r['loglevel4'] or 'informational'
            retval['log_interval'] = int(mm_r['log_interval1'] \
                or mm_r['log_interval2'] or mm_r['log_interval4'] or 300)

        return retval

# collect, format and write database Time-Range Configures
class SolveTimeRange:
    def __init__(self, firewall=None, file=None):
        reslist = []
        lines = file.readlines().__len__()
        file.seek(0)
        for i in range(lines):
            resdict = {}
            try:
                name = re.search('^time-range\s+(?P<time_range_name>\S+)', file.readline().rstrip('\n'))
                if name is not None:
                    resdict['name'] = name.groupdict()['time_range_name']
                    date_time = re.search('end\s+(?P<end_time>[^\&]+)', file.readline().rstrip('\n'))
                    end_time = datetime.strptime(date_time.groupdict()['end_time'], '%H:%M %d %B %Y')
                    resdict['end_time'] = end_time
                    reslist.append(resdict)
            except:
                print('init time_range fault %s' % name)
        self.firewall_name = firewall
        self.reslist = reslist
    def write_database(self):
        for i in self.reslist:
            try:
                name = i['name']
                end_time = i['end_time']
                time1 = TimeRange(firewall_name=self.firewall_name, name=name, end_datetime=end_time)
                time1.save()
            except:
                print('write time_range database error %s' % name)

# collect, format and write database Access-Group
class SolveAccessGroup:
    def __init__(self, firewall=None, file=None):
        reslist = []
        lines = file.readlines().__len__()
        file.seek(0)
        for i in range(lines):
            resdict = {}
            try:
                name = re.search('^access-group\s+(?P<access_group_name>\S+)\s+in\s+interface\s+(?P<interface>\S+)', file.readline().rstrip('\n'))
                if name is not None:
                    resdict['access_group'] = name.groupdict()['access_group_name']
                    resdict['interface'] = name.groupdict()['interface']
                    reslist.append(resdict)
            except:
                raise ValueError("Cannot Init AccessGroup and interface for '{0}'".format(i))
        self.firewall_name = firewall
        self.reslist = reslist
    def write_database(self):
        for i in self.reslist:
            try:
                record1 = AccessGroup(firewall_name=self.firewall_name, access_group=i['access_group'], interface=i['interface'])
                record1.save()
            except:
                raise ValueError("Cannot Write Database AccessGroup and interface for '{0}'".format(i))


##-------------  ASA object-group network Configures
##
_RE_NETOBJECT_STR = r"""(?:                         # Non-capturing parenthesis
 (^\s*network-object\s+host\s+(?P<host>\S+))
|(^\s*network-object\s+(?P<network>\S+)\s+(?P<netmask>\d+\.\d+\.\d+\.\d+))
|(^\s*group-object\s+(?P<groupobject>\S+))
)                                                   # Close non-capture parens
"""
_RE_NETOBJECT = re.compile(_RE_NETOBJECT_STR, re.VERBOSE)


class ASAObjGroupNetwork:

    def __init__(self, line):

        self.name = re.search(r'^object-group\s+network\s+(\S+)', line)


    def is_object_for(cls, line="", re=re):
        if 'object-group network ' in line[0:21].lower():
            return True
        return False

    def hash_children(self):
        ## Manually override the BaseCfgLine method since this recurses through
        ##    children
        ## FIXME: Implement hash_children for ASAObjGroupService
        return hash(tuple(self.network_strings))  # network_strings recurses...

    def network_count(self):
        ## Return the number of discrete network objects covered by this group
        ## FIXME: Implement port_count for ASAObjGroupService
        return len(self.network_strings)

    def network_strings(self):
        """Return a list of strings which represent the address space allowed by
        this object-group"""
        retval = list()
        names = self.confobj.names
        for obj in self.children:

            ## Parse out 'object-group ...' and 'group-object' lines...
            mm = _RE_NETOBJECT.search(line)
            if not (mm is None):
                net_obj = mm.groupdict()
                if net_obj['netmask']=='255.255.255.255':
                    net_obj['host'] = net_obj['network']
            else:
                net_obj = dict()

            if net_obj.get('host', None):
                retval.append(names.get(net_obj['host'],
                    net_obj['host']))
            elif net_obj.get('network', None):
                ## This is a non-host network object
                retval.append('{0}/{1}'.format(names.get(net_obj['network'],
                    net_obj['network']), net_obj['netmask']))
            elif net_obj.get('groupobject', None):
                groupobject = net_obj['groupobject']
                if groupobject==self.name:
                    ## Throw an error when importing self
                    raise ValueError("FATAL: Cannot recurse through group-object {0} in object-group network {1}".format(groupobject, self.name))

                group_nets = self.confobj.object_group_network.get(groupobject,
                    None)
                if (group_nets is None):
                    raise ValueError("FATAL: Cannot find group-object named {0}".format(name))
                else:
                    retval.extend(group_nets.network_strings)
            elif 'description ' in obj.text:
                pass
            else:
                raise NotImplementedError("Cannot parse '{0}'".format(obj.text))
        return retval

    def networks(self):
        """Return a list of IPv4Obj objects which represent the address space allowed by
        This object-group"""
        ## FIXME: Implement object caching for other ASAConfigList objects
        ## Return a cached result if the networks lookup has already been done

        retval = list()
        for net_str in self.network_strings:
            ## Check the ASACfgList cache of network objects
            if not self.confobj._network_cache.get(net_str, False):
                net = IPv4Obj(net_str)
                self.confobj._network_cache[net_str] = net
                retval.append(net)
            else:
                retval.append(self.confobj._network_cache[net_str])

        return retval