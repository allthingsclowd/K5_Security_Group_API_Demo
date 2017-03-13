#!/usr/bin/python
""" Fujitsu K5 Security Group Modification Demo
    
    This script shows how list all security groups in K5 OpenStack
    and then add some new rules

    Ensure to configure the necessary parameters in the k5contractsettingsV12.py
    file before execution  



Author: Graham Land
Date: 13/03/17
Twitter: @allthingsclowd
Github: https://github.com/allthingscloud
Blog: https://allthingscloud.eu


"""
from k5contractsettingsV12 import *
from k5regionapiv2 import *


def main():


    # Get a project scoped token
    k5token = get_scoped_token(adminUser, adminPassword, contract, targetProjectId, region)

    cidr = "0.0.0.0/0"

    # for rule in list_security_group_rules(k5token).json()['security_group_rules']:
    #     if ((rule.get('port_range_min') in [0,80,8080]) or (rule.get('protocol') == 'udp')):
    #         print rule, "\n"
    #         print delete_security_group_rule(k5token, rule.get('id'))

    # for rule in list_security_group_rules(k5token).json()['security_group_rules']:
    #     if rule.get('port_range_min') in [0,80,8080]:
    #         print rule, "\n"


    # Add new sg rules to ALL the security groups
    for sg in list_security_groups(k5token).json()['security_groups']:
        print "\n---Security Group Before Change----\n", sg, "\n"
        # Enable ingress (inbound) UDP on all ports from every ip address on the internet
        print create_security_group_rule(k5token, sg.get('id'), "ingress", None, None, "UDP", cidr)
        # Enable ingress (inbound) TCP port 80 only from every ip address on the internet 
        print create_security_group_rule(k5token, sg.get('id'), "ingress", 80, 80, "TCP", cidr)
        # Enable ingress (inbound) TCP port 8080 from every ip address on the internet
        print create_security_group_rule(k5token, sg.get('id'), "ingress", 8080, 8080, "TCP", cidr)

    for sg in list_security_groups(k5token).json()['security_groups']:
        print "\n---Security Group After Change----\n", sg, "\n"


    

if __name__ == "__main__":
    main()