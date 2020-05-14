
import xml.etree.ElementTree as etree
import os
import csv
import argparse
from collections import Counter
from time import sleep
from xerror.settings import BASE_DIR

csv_name = ""

def get_host_data(root):

    host_data = []
    hosts = root.findall('host')
    for host in hosts:
        addr_info = []

        # Ignore hosts that are not 'up'
        if not host.findall('status')[0].attrib['state'] == 'up':
            continue


        
        # Get IP address and host info. If no hostname, then ''
        ip_address = host.findall('address')[0].attrib['addr']
        host_name_element = host.findall('hostnames')
        try:
            host_name = host_name_element[0].findall('hostname')[0].attrib['name']
        except IndexError:
            host_name = ''
        
        try:
            os_element = host.findall('os')
            os_name = os_element[0].findall('osmatch')[0].attrib['name']
        except IndexError:
            os_name = ''
        
        # Get information on ports and services
        try:
            port_element = host.findall('ports')
            ports = port_element[0].findall('port')
            for port in ports:
                port_data = []

                proto = port.attrib['protocol']
                port_id = port.attrib['portid']
                service = port.findall('service')[0].attrib['name']
                # service_version = port.findall('service')[0].attrib['version']
                
                try:
                    product = port.findall('service')[0].attrib['product']
                except (IndexError, KeyError):
                    product = 'na'     

                try:
                    service_version = port.findall('service')[0].attrib['version']
                except (IndexError, KeyError):
                    service_version = 'na'    

                try:
                    servicefp = port.findall('service')[0].attrib['servicefp']
                except (IndexError, KeyError):
                    servicefp = 'na'
                try:
                    script_id = port.findall('scaript')[0].attrib['id']
                except (IndexError, KeyError):
                    script_id = 'na'
                try:
                    script_output = port.findall('script')[0].attrib['output']
                except (IndexError, KeyError):
                    script_output = 'na'

                # Create a list of the port data
                port_data.extend((ip_address, host_name, os_name,
                                  proto, port_id, service,service_version, product, 
                                  servicefp, script_id, script_output))
                
                # Add the port data to the host data
                host_data.append(port_data)

        except IndexError:
            addr_info.extend((ip_address, host_name))
            host_data.append(addr_info)
    return host_data

def parse_xml(filename):

    try:
        tree = etree.parse(filename)
    except Exception as error:
        print("[-] A an error occurred. The XML may not be well formed. "
              "Please review the error and try again: {}".format(error))
        exit()
    root = tree.getroot()
    scan_data = get_host_data(root)
    return scan_data


def parse_to_csv(data,namee):
    """Given a list of data, adds the items to (or creates) a CSV file."""
    pth = BASE_DIR + '/reports/' + csv_name
    if not os.path.isfile(namee):
        csv_file = open(namee, 'wb')
        csv_writer = csv.writer(csv_file)
        top_row = [
            'IP', 'Host', 'os', 'Proto', 'Port',
            'Service','Service_version', 'Product', 'Service FP',
            'NSE Script ID', 'NSE Script Output', 'Notes'
        ]
        csv_writer.writerow(top_row)
        print('\n[+] The file {} does not exist. New file created!\n'.format(
                csv_name))
    # else:
    #     # try:
    #     csv_file = open(csv_name, 'w')

    #     csv_writer = csv.writer(csv_file)
    #     print('\n[+] {} exists. Appending to file!\n'.format(csv_name))

        
    for item in data:
        csv_writer.writerow(item)
    csv_file.close()        

def list_ip_addresses(data):
    """Parses the input data to return only the IP address information"""
    ip_list = [item[0] for item in data]
    sorted_set = sorted(set(ip_list))
    addr_list = [ip for ip in sorted_set]
    return addr_list

def nmxmlparser(xmlRepo,csName):
    csv_name = csName

    # filename = "twohost.xml"
    fle  = BASE_DIR + '/reports/' + xmlRepo
    fle_csv  = BASE_DIR + '/reports/' + csName
    filename = fle
    if filename:

        data = parse_xml(filename)
        if not data:
            print("[*] Zero hosts identitified as 'Up' or with 'open' ports. "
                  "Use the -u option to display ports that are 'open|filtered'. "
                  "Exiting.")
            exit()
        # if args.csv:
        print("start csv conversion")
        parse_to_csv(data,fle_csv)
        return "Xml parsing Done"

# if __name__ == '__main__':

#     csv_name = "abcdef.csv"
#     main()
