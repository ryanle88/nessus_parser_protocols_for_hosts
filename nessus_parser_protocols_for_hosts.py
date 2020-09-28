#!/usr/bin/env python

import csv
import pprint
import re
import sys
import argparse
from pathlib import Path
import json
from defusedxml.ElementTree import fromstring as parsexmlstring
from defusedxml.cElementTree import iterparse as xmliterparse

ident_regex = re.compile("Remote operating system : (.+)", re.IGNORECASE)
device_type_regex = re.compile("Remote device type : (.+)", re.IGNORECASE)
add_hostnames_regex = re.compile("^-(.+)$", re.IGNORECASE)

pp = pprint.PrettyPrinter(indent=4)


class Vulnerability(object):
    def __init__(
        self,
        id,
        name,
        plugin_id,
        service_id,
        service_name,
        severity,
        risk,
        solution,
        output=None,
        props=None,
    ):
        self.id = id
        self.name = name
        self.plugin_id = plugin_id
        self.service_id = service_id
        self.service_name = service_name
        self.severity = severity
        self.risk = risk
        self.props = props or {}
        self.output = output or ""
        self.solution = solution or ""

    @classmethod
    def from_item(cls, item):
        plugin_id = item.attrib["pluginID"]
        port = item.attrib["port"]
        proto = item.attrib["protocol"]
        service_id = "{}_{}".format(proto, port)
        vuln_id = "{}_{}_{}".format(proto, port, plugin_id)
        name = item.attrib["pluginName"]
        service_name = item.attrib["svc_name"]
        severity = item.attrib["severity"]
        output = []
        risk = ""
        props = {}
        solution = ""
        for param in item:
            if param.tag == "plugin_output":
                output.append(param.text)

            if param.tag == "risk_factor":
                risk = param.text.lower()

            if param.tag == "cve":
                if "cve" in props:
                    props["cves"].append(param.text)
                else:
                    props["cves"] = [param.text]
                continue
            if param.tag == "solution":
                solution = param.text
            props[param.tag] = param.text

        output = " ".join(output)

        return cls(
            vuln_id,
            name,
            plugin_id,
            service_id,
            service_name,
            severity,
            risk,
            solution,
            output,
            props,
        )

    def __repr__(self):
        return "Vulnerability(id={})".format(self.id)


class Service(object):
    def __init__(self, port, protocol, id=None):
        self.id = id or "{}_{}".format(protocol, port)
        self.port = port
        self.protocol = protocol
        self._real_asset = None  # typically uuid

    def __repr__(self):
        return "Service(port={}, protocol={})".format(self.port, self.protocol)


class Host(object):
    def __init__(
        self,
        name=None,
        ip=None,
        netbios=None,
        fqdn=None,
        mac=None,
        props=None,
        vulns=None,
        services=None,
    ):
        if props == None:
            props = {}
        if not ip and "host-ip" in props:
            ip = props["host-ip"]
        if not fqdn and "host-fqdn" in props:
            fqdn = props["host-fqdn"]
        if not mac and "mac-address" in props:
            mac = props["mac-address"]
        if not netbios and "netbios-name" in props:
            netbios = props["netbios-name"]
        self.name = name or "unknown"
        self.ip = ip
        self.fqdn = fqdn
        self.netbios = netbios
        self.mac = mac
        self.props = props
        self.more_props = []
        self.vulns = vulns or []
        self.services = services or []
        self._real_asset = None  # typically uuid

    def merge(self, target):
        if not self.ip and target.ip:
            self.ip = target.ip
        if not self.fqdn and target.fqdn:
            self.fqdn = target.fqdn
        if not self.mac and target.mac:
            self.mac = target.mac
        if not self.netbios and target.netbios:
            self.netbios = target.netbios
        if target.props not in self.more_props:
            self.more_props.append(target.props)

    def has_service(self, service):
        service = self.get_service(service)
        if not service:
            return False
        return True

    def get_risks(self, level):
        vulns = []
        for vuln in self.vulns:
            if vuln.risk == level:
                vulns.append(vuln)
        return vulns

    def has_risk(self, level):
        for vuln in self.vulns:
            if vuln.risk == level:
                return True
        return False

    def has_vuln_by_plugin(self, plugin_id):
        for vuln in self.vulns:
            if vuln.plugin_id == plugin_id:
                return True
        return False

    def get_service(self, service):
        for serv in self.services:
            if serv.port == service.port and serv.protocol == service.protocol:
                return serv
        return None

    def add_service(self, service):
        self.services.append(service)

    def add_vuln(self, vuln):
        self.vulns.append(vuln)

    def get_additional_dnsnames(self):
        for vuln in self.vulns:
            if vuln.name == "Additional DNS Hostnames":
                return vuln
        return None

    def get_os_ident(self):
        for vuln in self.vulns:
            if vuln.name == "OS Identification":
                return vuln
        return None

    def get_device_type(self):
        for vuln in self.vulns:
            if vuln.name == "Device Type":
                return vuln
        return None

    def get_device_type_name(self):
        device_type = self.get_device_type()
        if not device_type:
            return "unknown"
        needle = device_type_regex.search(device_type.output)
        if needle:
            if len(needle.groups()) > 0:
                return needle.group(1)
        return "unknown"

    def get_os_ident_name(self):
        ident = self.get_os_ident()
        if not ident:
            if "operating-system" in self.props:
                if self.props["operating-system"]:
                    return self.props["operating-system"]
            for other_props in self.more_props:
                if "operating-system" in other_props:
                    if other_props["operating-system"]:
                        return other_props["operating-system"]
            if "os" in self.props:
                if self.props["os"]:
                    return self.props["os"]
            for other_props in self.more_props:
                if "os" in other_props:
                    if other_props["os"]:
                        return other_props["os"]
            return "unknown"
        needle = ident_regex.search(ident.output)
        if needle:
            if len(needle.groups()) > 0:
                return needle.group(1)
        return "unknown"

    def get_fqdn_or_ip(self):
        if self.fqdn:
            return self.fqdn
        if self.ip:
            return self.ip
        return "unkown"

    def get_name(self):
        if self.fqdn:
            if "." in self.fqdn:
                return self.fqdn.split(".")[0].upper()
            else:
                return self.fqdn
        if self.netbios:
            return self.netbios
        add_hostnames = self.get_additional_dnsnames()
        if add_hostnames:
            output = add_hostnames.output
            needle = add_hostnames_regex.search(output)
            if needle:
                if len(needle.groups()) > 0:
                    return needle.group(1)
        if self.ip:
            return self.ip
        return self.name

    def __repr__(self):
        return "Host(ip={},fqdn={})".format(self.ip, self.fqdn)

    @classmethod
    def from_props(cls, name, props):
        return cls(name, props=props)


class HostBag(object):
    def __init__(self):
        self.hosts = []

    def has_host(self, target):
        host = self.get_host(target)
        if not host:
            return False
        return True

    def get_by_name(self, name):
        for host in self.hosts:
            if name.upper() == host.get_name().upper():
                return host
        return None

    def get_host(self, target):
        for host in self.hosts:
            if target.ip and target.ip == host.ip:
                return host
            elif target.fqdn and target.fqdn == host.fqdn:
                return host
            elif target.mac and target.mac == host.mac:
                return host
        return None

    def update_host(self, host, target):
        host = self.get_host(host)
        if not host:
            return False
        host.merge(target)
        return True

    def add_host(self, target):
        self.hosts.append(target)

    def __repr__(self):
        return "HostBag(count={})".format(len(self.hosts))


class NessusParser(object):
    @classmethod
    def parse(cls, file):
        if isinstance(file, str):
            file_path = Path(file)
            content = file_path.read_text()
        else:
            content = file.read().decode("utf-8")
            file.close()
        root = parsexmlstring(content)
        # print("~~~~~~~cls.parse_root(root): ", cls.parse_root(root))
        return cls.parse_root(root)

    @classmethod
    def parse_root(cls, root):
        bag = HostBag()
        for block in root:
            # nessus groups xml by host
            if block.tag == "Report":
                for report_host in block:
                    host_name = report_host.attrib["name"]
                    for report_item in report_host:
                        if report_item.tag == "HostProperties":
                            host_props_dict = {}
                            for host_properties in report_item:
                                attrib_name = host_properties.attrib["name"]
                                host_props_dict[attrib_name] = host_properties.text
                        new_host = Host.from_props(host_name, host_props_dict)
                        if bag.has_host(new_host):
                            host = bag.get_host(new_host)
                            bag.update_host(host, new_host)
                        else:
                            bag.add_host(new_host)
                            host = new_host
                    # loop over report_item a second time
                    if host:
                        for report_item in report_host:
                            if (
                                "protocol" in report_item.attrib
                                and "port" in report_item.attrib
                            ):

                                proto = report_item.attrib["protocol"]
                                port = report_item.attrib["port"]
                                service = Service(port, proto)

                                if not host.has_service(service):
                                    host.add_service(service)

                                vuln = Vulnerability.from_item(report_item)

                                host.add_vuln(vuln)
                    else:
                        print("No Host found...")
        return bag


####### Refactor to simple parsing


class NessusSimpleItem(object):
    def __init__(
        self,
        title="",
        description="",
        port=0,
        protocol="tcp",
        severity=0,
        risk="INFORMATIONAL",
        impact="MINOR",
        likelihood="LOW",
        plugin_id=None,
        finding_code=None,
        cves="",
        output="",
        remediation="",
        exploit_available="",
        references=None,
        fname="",
    ):
        self.title = title
        self.description = description
        self.port = port
        self.protocol = protocol
        self.severity = severity
        self.risk = risk
        self.likelihood = likelihood
        self.impact = impact
        self.finding_code = finding_code or ""
        self.plugin_id = plugin_id or ""
        self.cves = cves
        self.remediation = remediation
        self.exploit_available = exploit_available
        self.output = output
        self.references = references or []
        self.fname = fname

    @classmethod
    def parse(cls, block):
        title = ""
        description = ""
        exploit_available = ""
        port = int(block.attrib["port"])
        protocol = block.attrib["protocol"]
        severity = int(block.attrib["severity"])
        risk = "INFORMATIONAL"
        likelihood = "LOW"
        impact = "MINOR"
        fname = ""

        if severity == 4 or severity > 4:
            risk = "CRITICAL"
            impact = "MAJOR"
            likelihood = "HIGH"

        elif severity == 3:
            risk = "SERIOUS"
            impact = "MODERATE"
            likelihood = "MODERATE"

        elif severity == 2:
            risk = "MEDIUM"
            impact = "MODERATE"
            likelihood = "MODERATE"

        elif severity == 1:
            risk = "LOW"

        plugin_id = block.attrib["pluginID"]
        finding_code = "NESSUS_" + str(plugin_id)
        output = []
        cves = []
        remediation = ""
        references = [
            "https://www.tenable.com/plugins/nessus/{}".format(str(plugin_id))
        ]

        for child in block:
            if child.tag == "plugin_output":
                output.append(child.text)
            elif child.tag == "cve":
                cves.append(child.text)
            elif child.tag == "solution":
                remediation = child.text
            elif child.tag == "see_also":
                references.append(child.text)
            elif child.tag == "plugin_name":
                title = child.text
            elif child.tag == "description":
                description = child.text
            elif child.tag == "exploit_available":
                exploit_available = child.text
            elif child.tag == "fname":
                fname = child.text

        output = " ".join(output)
        params = dict(
            title=title,
            description=description,
            port=port,
            protocol=protocol,
            severity=severity,
            risk=risk,
            impact=impact,
            likelihood=likelihood,
            finding_code=finding_code,
            plugin_id=plugin_id,
            cves=cves,
            remediation=remediation,
            exploit_available=exploit_available,
            output=output,
            fname=fname,
        )

        return cls(**params)

    def __repr__(self):
        return "{} ({}:{}/{})".format(
            self.__class__.__name__, self.title, str(self.port), self.protocol
        )


class NessusSimpleHost(object):
    def __init__(
        self,
        name=None,
        fqdn=None,
        ip_address=None,
        tags=None,
        items=None,
        ports=None,
        protocols=None,
    ):
        self.name = name
        self.fqdn = fqdn
        self.ip_address = ip_address
        self.tags = tags
        self.items = items
        self.ports = ports
        self.protocols = protocols

    @classmethod
    def parse(cls, block):
        name = block.attrib["name"]
        fqdn = None
        ip_address = None
        tags = {}
        items = []
        ports = set()
        protocols = set()
        for child in block:
            if child.tag == "HostProperties":
                for hp_child in child:
                    if hp_child.tag == "tag":
                        tags[hp_child.attrib["name"]] = hp_child.text

                    if hp_child.tag == "tag" and hp_child.attrib["name"] == "host-fqdn":
                        fqdn = hp_child.text
                    if hp_child.tag == "tag" and hp_child.attrib["name"] == "host-ip":
                        ip_address = hp_child.text
            elif child.tag == "ReportItem":
                item = NessusSimpleItem.parse(child)
                if item.port != 0:
                    ports.add(item.port)
                protocols.add(item.protocol)
                items.append(item)
        return cls(
            name=name,
            fqdn=fqdn,
            ip_address=ip_address,
            tags=tags,
            items=items,
            ports=list(ports),
            protocols=list(protocols),
        )

    def __repr__(self):
        return "{} ({})".format(self.__class__.__name__, self.name)


class NessusSimpleBag(object):
    def __init__(self, hosts):
        self.hosts = hosts

    @classmethod
    def get_root(cls, file):
        if isinstance(file, Path):
            content = file.read_text()
        elif isinstance(file, str):
            content = Path(file).read_text()
        else:
            content = file.read().decode("utf-8")
            file.close()
        return parsexmlstring(content)

    @classmethod
    def get_root_iter(cls, file, tag="ReportHost"):
        context = xmliterparse(file, events=("start", "end"))
        # turn it into an iterator
        context = iter(context)
        # get the root element
        event, root = context.__next__()
        for event, elem in context:
            if event == "end" and elem.tag == tag:
                yield elem
                root.clear()
        return

    @classmethod
    def parse(cls, file, type="all"):
        hosts = []
        for block in cls.get_root(file):
            if block.tag == "Report":
                for host_block in block:
                    host = NessusSimpleHost.parse(host_block)
                    hosts.append(host)
        return cls(hosts)

    # gets 1
    @classmethod
    def iter(cls, file):
        for host_block in cls.get_root_iter(file, tag="ReportHost"):
            yield NessusSimpleHost.parse(host_block)
        return

    # gets x
    @classmethod
    def chunks(cls, file, fetch=1000):
        hosts = []
        for host_block in cls.get_root_iter(file, tag="ReportHost"):
            host = NessusSimpleHost.parse(host_block)
            hosts.append(host)
            if len(hosts) == fetch:
                yield hosts
                hosts = []
        yield hosts
        return


class NessusSimpleParser(object):
    @classmethod
    def parse(cls, file):
        return NessusSimpleBag.parse(file)

    @classmethod
    def iter(cls, file):
        for host in NessusSimpleBag.iter(file):
            yield host
        return

    @classmethod
    def chunks(cls, file, fetch=1000):
        for hostchunk in NessusSimpleBag.chunks(file, fetch=fetch):
            yield hostchunk
        return


def run(file_path, output):
    with open(output + ".csv", "w+") as csv_file:
        header = ["Host", "Ports", "Protocols", "FQDN"]
        writer = csv.DictWriter(csv_file, fieldnames=header)
        writer.writeheader()
        nessus_bag = NessusSimpleParser.parse(file_path)

        for host in nessus_bag.hosts:
            ports = host.ports
            ports.sort()
            string_ports = [str(i) for i in ports]
            protocols = host.protocols
            protocols.sort()
            writer.writerow(
                {
                    "Host": host.ip_address,
                    "Ports": ", ".join(string_ports),
                    "Protocols": ", ".join(protocols),
                    "FQDN": host.fqdn,
                }
            )

    print(f"[!] Parsing successfully. New file {output + '.csv'} has been created.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-f", "--file", required=True, type=str, help="Path of nessus file"
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="results",
        help="Output location base path (do not include .csv or .json)",
    )

    args = parser.parse_args()

    try:
        with open(args.output + ".csv", "w") as f:
            pass
    except IOError as x:
        print(
            "[!] Potential output file cannot be opened or accessed. Please select a different output location"
        )
        sys.exit(1)

    sys.exit(run(args.file, args.output))
