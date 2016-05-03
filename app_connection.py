#!/usr/bin/env python
import argparse
import boto3
import json
import logging
import os
import sys
import traceback


class InstanceRelationship(object):
    isInstances = False
    obj_1 = None
    obj_2 = None

    obj_1_to_2_ports = []
    obj_2_to_1_ports = []

    obj_1_elbs = []
    obj_2_elbs = []
    error = None


################################
# Function to gather data
################################
def get_instance_sgs(instance_id):
    sgs = []
    try:
        response = ec2_client.describe_instances(
            InstanceIds=[instance_id]
        )
    except Exception as e:
        raise Exception('Describe instance failed.')

    if len(response['Reservations']) > 0:
        for sg in response['Reservations'][0]['Instances'][0]['SecurityGroups']:
            sgs.append(sg['GroupId'])
    else:
        raise ReferenceError('Instance ' + instance_id + ' no longer exist, or was not found.')
    return sgs


# Todo: error handling
def describe_sg(security_group_ids):
    sgs_data = {'group_ids': [], 'ip_permissions': [], 'ip_permissions_egress': [], 'vpc_id': None}
    sgs_data['group_ids'].append(security_group_ids)
    for security_group_id in security_group_ids:
        sg = ec2.SecurityGroup(security_group_id)
        sgs_data['ip_permissions'].extend(sg.ip_permissions)
        sgs_data['ip_permissions_egress'].extend(sg.ip_permissions_egress)
        sgs_data['vpc_id'] = sg.vpc_id
    return sgs_data


################################
# Comparison FUnctions
################################
# TODO: account ofr different user IDs with SGs
# -1 is wild card for ports in AWS
def compare_sg_rules(sg_1, sg_2):
    # run through check list

    # 1) are they in same vpc?  Future plan would check cross vpc talk
    if sg_1['vpc_id'] != sg_2['vpc_id']:
        return 'Items being compared in different VPCs'



def main():
    if arguments.Security_Groups is None:
        instance1_sg = describe_sg(get_instance_sgs(arguments.Instances[0][0]))
        instance2_sg = describe_sg(get_instance_sgs(arguments.Instances[0][1]))
    else:
        instance1_sg = describe_sg([arguments.Security_Groups[0][0]])
        instance2_sg = describe_sg([arguments.Security_Groups[0][1]])

    results = compare_sg_rules(instance1_sg, instance2_sg)


    return


if __name__ == "__main__":
    # Arguments
    parser = argparse.ArgumentParser(description='Checks if two machines in AWS have '
                                                 'permission to talk with each other on specified port.')
    parser.add_argument('-p', '--port', action='store', dest='Port', required=False, default=80,
                        help='Port to check for connectivity permission.')
    parser.add_argument('-r', '--region', action='store', dest='Region', required=True,
                        help='Region to evaluate resources in.')
    instance_or_sg = parser.add_mutually_exclusive_group(required=True)
    instance_or_sg.add_argument('-i', '--instance_ids', action='append', dest='Instances',
                                nargs='*', help='ID of 2 instances to check connectivity permissions between them.')
    instance_or_sg.add_argument('-sg', '--security_group_ids', action='append', dest='Security_Groups',
                                nargs='*', help='ID of 2 SGs to check connectivity permissions between them.')
    arguments = parser.parse_args()

    ec2_client = boto3.client('ec2', arguments.Region)
    ec2 = boto3.resource('ec2', arguments.Region)
    client = boto3.client('elb', arguments.Region)

    main()
    sys.exit(0)


