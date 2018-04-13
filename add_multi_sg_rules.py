#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
author: firxiaowork@gmail.com
usage: add multi-sg rules to multi-destination
"""

import boto3
import re
from botocore.exceptions import ClientError
import json
import configparser
import yaml
from tabulate import tabulate


# adapt input in python2.x and python3.x
try:
   input = raw_input
except NameError:
   pass

# function: search sg via ec2 name
def search_ec2_sg(keywords):
    """
    :param keyword:
    :return: sg list
    """
    ec2 = session.resource('ec2')
    # get ec2 id name and sg
    results=[]
    for instance in ec2.instances.all():
        if instance.tags != None:
            for tag in instance.tags:
                 #print(tag)
                if tag["Key"] != None:
                    if tag["Key"] == "Name":
                        if tag["Value"] != None:
                            ec2_name = tag["Value"]
                            #print(ec2_name,keyword)
                            if re.search(keywords,ec2_name) is not None:
                                for sg in instance.security_groups:
                                    if re.search("basic",sg["GroupName"]) is None:
                                        ec2_info = (instance.id, ec2_name, sg["GroupId"])
                                        results.append(ec2_info)

        else:
            pass
    return results

# function: search sg via sg name
def search_sg(keywords):
    """
    :param keywords:
    :return:  sg list
    """
    results = []
    response = ec2_client.describe_security_groups(
        Filters=[
            {
                'Name': 'group-name',
                'Values': [
                    '*'+ keywords +'*',
                ]
            },
    ],
    )
    #print(results["SecurityGroups"])
    # print(results)
    if response["SecurityGroups"]:
        for sg in response["SecurityGroups"]:
            groupname = sg["GroupName"]
            groupnid = sg["GroupId"]
            ownerid = sg["OwnerId"]
            #print(ownerid,groupname,groupnid)
            sg_info = (ownerid,groupname,groupnid)
            results.append(sg_info)
    else:
        print("There is no SG name contain %s!!!"%(keywords))
    return results

# function: input source ip
def input_src_ips():
    """
    :return: src_ips
    """
    src_ips = []
    while True:
        ip = str(input("Please input srouce IP: "))
        confirm_add_ip = input("Do you want to add another IP? y/n: ")
        src_ips.append(ip)
        if confirm_add_ip == "n":
            break
        # print(ips)
    return src_ips

# function: create a menu of list
def create_menu(_list):
    """
    :param _list:
    :return: choice
    """
    for i,option in enumerate(_list):
        print('%d: %s' % (i + 1, option))
        lr = len(_list)
    choice = int(input('Enter your choice [1-%d] : ' % (lr)))
    print("You choosen %d: %s!"%(choice,_list[choice-1]))
    return _list[choice-1]


# function: add sg rule
# support source type: sg and ip
def add_sg_rule(rule,source_type,dryrun=True):
    """
    :param rule:
    :param source_type:
    :return:
    """
    if source_type == "sg":
        uid = rule[1]
        src = rule[2]
        dest = rule[4]
        proto = rule[5]
        from_port = rule[6]
        to_port = rule[7]
        describe = rule[8]
        data = ec2_client.authorize_security_group_ingress(
            GroupId=dest,
            IpPermissions=[
                {'IpProtocol': proto,
                 'FromPort': from_port,
                 'ToPort': to_port,
                 'UserIdGroupPairs': [
                     {
                         'Description': describe,
                         'GroupId': src,
                         'UserId': uid
                     },
                 ],
                 },
            ],
            DryRun=dryrun
        )
        print('Ingress Successfully Set %s' % data)
    elif source_type == "ip":
        ip = rule[0]
        dest = rule[2]
        proto = rule[3]
        from_port = rule[4]
        to_port = rule[5]
        describe = rule[6]
        data = ec2_client.authorize_security_group_ingress(
            GroupId=dest,
            IpPermissions=[
                {'IpProtocol': proto,
                 'FromPort': from_port,
                 'ToPort': to_port,
                 'IpRanges': [
                     {
                         'CidrIp': ip,
                         'Description': describe
                     },
                 ],
                 },
            ],
            DryRun=dryrun
        )
        print('Ingress Successfully Set %s' % data)



# function: input sg rules
def input_rules():
    """
    :param src:
    :param dest:
    :param proto:
    :param from_port:
    :param to_port:
    :param describe:
    :return: list
    """
    #print("src", "dest", "proto", "from prot", "to port", "describe")
    sg_rules = []
    while True:
        proto = str(input("Please input protocol, eg: tcp udp : "))
        from_port = int(input("Please input from port: "))
        to_port = int(input("Please input to port: "))
        describe = str(input("Please input describe: "))
        #rule = (src, dest, proto, from_port, to_port, describe)
        rule = (proto, from_port, to_port, describe)
        sg_rules.append(rule)
        confirm_add_rule = input("Do you want add another rule? y/n: ")
        if confirm_add_rule == "n":
            break
        #print(src_sg[2], dest_sg[2], proto, from_port, to_port, describe)
    return sg_rules



# function: generate sg rules from iupt
def gen_final_rules(source_type):
    final_rules = []
    rules = input_rules()
    if source_type == "sg":
        for rule in rules:
            for src_sg in src_sgs:
                for dest_sg in dest_sgs:
                    rule_info = ((src_sg[1], src_sg[0], src_sg[2], dest_sg[1], dest_sg[2]) + rule)
                    # print(rule_info)
                    final_rules.append(rule_info)
        # print(rules)
        print(" ")
        print("Please review your rules: ")
        print(tabulate(final_rules,
                       headers=["src sg name", "src sg uid", "src sg", "dest sg name", "dest sg", "proto", "from prot",
                                "to port", "describe"]))
    elif source_type == "ip":
        for rule in rules:
            for src_ip in src_ips:
                for dest_sg in dest_sgs:
                    rule_info = ((src_ip, dest_sg[1], dest_sg[2]) + rule)
                    # print(rule_info)
                    final_rules.append(rule_info)
        print(" ")
        print("Please review your rules: ")
        print(tabulate(final_rules,
                       headers=["src ip", "dest sg name", "dest sg", "proto", "from prot",
                                "to port", "describe"]))
    #print(final_rules)
    return final_rules

# function: switch environment
def switch_env(environment):
    with open("config.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
    print("Please choose %s sg environment:"%(environment))
    print("Please choose region:")

    for i, region in enumerate(cfg):
        print('%d: %s' % (i + 1, region))

    lr = len(cfg)
    choice = int(input('Enter your choice [1-%d] : ' % (lr)))
    while True:
        if not choice: break
        region = list(cfg)[choice - 1]
        # print(region);
        # print(cfg[region])
        for i, d in enumerate(cfg[region]):
            # for k in env:
            #     print(k,env[k])
            print('%d: %s' % (i + 1, d['env']))
        le = len(cfg[region])
        choice = int(input('Enter your choice [1-%d] : ' % (le)))
        print('You choose %s !!!' % (list(cfg[region])[choice - 1]['env']))
        env = list(cfg[region])[choice - 1]['env']
        return region,env
        print(region,env)
        break

# function: choose source sgs from search results
def input_src_sgs():
    src_sgs = []
    while True:
        src_keywords = str(input("Please input keyword of source sg: "))
        if src_keywords:
            if search_sg(src_keywords):
                src_sg_info = create_menu(search_sg(src_keywords))
                src_sgs.append(src_sg_info)
                confirm_add_src = input("Do you want to add another source sg? y/n: ")
                if confirm_add_src == "n":
                    break
    return src_sgs
    # print(src_sgs)

# function: choose destination sgs from search results
def input_dest_sgs():
    dest_sgs = []
    while True:
        dest_keywords = str(input("Please input keyword of destination sg: "))
        if dest_keywords:
            if search_sg(dest_keywords):
                dest_sg_info = create_menu(search_sg(dest_keywords))
                dest_sgs.append(dest_sg_info)
                confirm_add_dest = input("Do you want to add another destination sg? y/n: ")
                if confirm_add_dest == "n":
                    break
    return dest_sgs

# main function start
# define source sg type
print("Please choose source sg type:")
src_types = ("sg","ip")
src_type = create_menu(src_types)
# choose source env and get source sgs or ips
if src_type == "sg":
    try:
        region, env = switch_env("source")
        session = boto3.Session(profile_name=env, region_name=region)
        ec2_client = session.client('ec2')
    except:
        print("%s is not found" % (env))
        exit(1)
    src_sgs = input_src_sgs()
elif src_type == "ip":
    src_ips = input_src_ips()

# choose dest env and get destination sgs info
try:
    region, env = switch_env("destination")
    session = boto3.Session(profile_name=env, region_name=region)
    ec2_client = session.client('ec2')
except:
    print("%s is not found" % (env))
    exit(1)

dest_sgs = input_dest_sgs()

# generate rules from source and destination info
rules = gen_final_rules(src_type)

# add rules in destination sg
# dryrun true
confirm = input("Do you want to do a dryrun test: y/n: ")
if confirm == "y":
    for rule in rules:
        try:
            add_sg_rule(rule,src_type, True)
        except ClientError as e:
            if 'DryRunOperation' not in str(e):
                raise

# dryrun false
confirm = input("Do you want to continue: y/n: ")
if confirm == 'y':
    for rule in rules:
        try:
            response = add_sg_rule(rule,src_type,False)
            print(response)
        except ClientError as e:
            print(e)
