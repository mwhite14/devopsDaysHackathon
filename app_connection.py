#!/usr/bin/env python
import argparse
import boto3
import sys


################################
# Helper Functions
################################
def get_mutual_elbs(elbs_1, elbs_2):
    mutual_elbs = {}
    for key1, value1 in elbs_1.iteritems():
        for key2 in elbs_2.iterkeys():
            if key1 == key2:
                mutual_elbs[key1] = value1
    return mutual_elbs


def find_path(sg_1_to_elb, elb_to_sg_1, sg_2_to_elb, elb_to_sg_2, instance_behind_elb):
    sg_mapping = {'sg_1': {}, 'sg_2': {}}
    # find sg_1 to _sg_2
    if instance_behind_elb != 1:
        for protocol in sg_1_to_elb:
            if protocol in elb_to_sg_2:
                intersect = sg_1_to_elb[protocol] & elb_to_sg_2[protocol]
                if len(intersect) > 0:
                    if protocol not in sg_mapping['sg_1']:
                        sg_mapping['sg_1'][protocol] = set()
                    sg_mapping['sg_1'][protocol] |= intersect

    if instance_behind_elb != 2:
        for protocol in sg_2_to_elb:
            if protocol in elb_to_sg_1:
                intersect = sg_2_to_elb[protocol] & elb_to_sg_1[protocol]
                if len(intersect) > 0:
                    if protocol not in sg_mapping['sg_2']:
                        sg_mapping['sg_2'][protocol] = set()
                    sg_mapping['sg_2'][protocol] |= intersect
    return sg_mapping


def get_port_range(port_set):
    p = []
    last = -2
    start = -1

    for item in port_set:
        if item != last + 1:
            if start != -1:
                p.append([start, last])
            start = item
        last = item

    p.append([start, last])
    s = ""
    for range in p:
        if range[0] == range[1]:
            s += str(range[0]) + ", "
        else:
            s += str(range[0])+'-'+str(range[1])+', '

    s = s[:-2]
    return s


def print_results(results, item1, item2):
    no_paths_found = True
    if len(results['sg_1_to_2_direct']) > 0:
        no_paths_found = False
        for protocol in results['sg_1_to_2_direct'].iterateitems():
            print(item1 + ' can talk to ' + item2 + ' via ' + (protocol +' on ports: ' + get_port_range(list(results['sg_1_to_2_direct'][protocol])) if protocol != -1 else 'All Ports'))

    if len(results['elbs']) > 0:
        no_paths_found = False
        for elb in results['elbs']:
            if len(results['elbs'][elb]['sg_1']) > 0:
                for protocol in results['elbs'][elb]['sg_1']:
                    print(item1 + ' can talk to ' + item2 + ' through ELB "' + elb + '" via ' +(
                    protocol + ' on ports: ' + get_port_range(list(results['elbs'][elb]['sg_1'][protocol])) if protocol != -1 else 'All Ports'))

    print("")
    if len(results['sg_2_to_1_direct']) > 0:
        no_paths_found = False
        for protocol in results['sg_2_to_1_direct']:
            print(item2 + ' can talk to ' + item1 + ' via ' + (protocol + ' on ports: ' + get_port_range(list(results['sg_2_to_1_direct'][protocol])) if protocol != -1 else 'All Ports'))

    if len(results['elbs']) > 0:
        no_paths_found = False
        for elb in results['elbs']:
            if len(results['elbs'][elb]['sg_2']) > 0:
                for protocol in results['elbs'][elb]['sg_2']:
                    print(item2 + ' can talk to ' + item1 + ' through ELB "' + elb + '" via ' + (
                        protocol + ' on ports: ' + get_port_range(
                            list(results['elbs'][elb]['sg_2'][protocol])) if protocol != -1 else 'All Ports'))

    if no_paths_found:
        print(item1 + ' can not talk to ' + item2)


################################
# Functions to gather data
################################
# TODO: may want to consider IP addresses of EIP/ENI
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
    sgs_data['group_ids'].extend(security_group_ids)
    for security_group_id in security_group_ids:
        sg = ec2.SecurityGroup(security_group_id)
        sgs_data['ip_permissions'].extend(sg.ip_permissions)
        sgs_data['ip_permissions_egress'].extend(sg.ip_permissions_egress)
        sgs_data['vpc_id'] = sg.vpc_id
    return sgs_data


def find_elbs_surrounding_sg(sg):
    associated_sgs = set()
    for ingress in sg['ip_permissions']:
        for group in ingress['UserIdGroupPairs']:
            associated_sgs.add(group['GroupId'])

    for egress in sg['ip_permissions_egress']:
        for group in egress['UserIdGroupPairs']:
            associated_sgs.add(group['GroupId'])

    elb_sgs = {}
    response = elb_client.describe_load_balancers()
    while True:
        for elb in response['LoadBalancerDescriptions']:
            for elb_sg in elb['SecurityGroups']:
                if elb_sg in associated_sgs:
                    if elb['LoadBalancerName'] not in elb_sgs:
                        elb_sgs[elb['LoadBalancerName']] = []
                    elb_sgs[elb['LoadBalancerName']].append(elb_sg)
        try:
            response = elb_client.describe_load_balancers(Marker=response['NextMarker'])
        except:
            break

    elb_data = {}
    for key, value in elb_sgs.iteritems():
        elb_data[key] = describe_sg(value)

    return elb_data


# returns if instance 1 or 2
def find_which_instance_is_behind_elb(elb_name, instance1, instance2):
    response = elb_client.describe_load_balancers(LoadBalancerNames=[elb_name])

    for instance in response['LoadBalancerDescriptions'][0]['Instances']:
        if instance['InstanceId'] == instance1:
            return 1
        if instance['InstanceId'] == instance2:
            return 2
    return 0


################################
# Comparison FUnctions
################################
# TODO: account for different user IDs with SGs
# -1 is wild card for ports in AWS
def compare_sg_rules(sg_1, sg_2):
    # run through check list

    # 1) are they in same vpc?  Future plan would check cross vpc talk
    if sg_1['vpc_id'] != sg_2['vpc_id']:
        return 'Items being compared in different VPCs'

    # 2) can they talk directly to each other?
    ports_1_to_2 = ports_a_can_talk_to_b(sg_1, sg_2)
    ports_2_to_1 = ports_a_can_talk_to_b(sg_2, sg_1)

    # 3) Are they behind elbs?
    elbs_1 = find_elbs_surrounding_sg(sg_1)
    elbs_2 = find_elbs_surrounding_sg(sg_2)
    elbs = get_mutual_elbs(elbs_1, elbs_2)

    elb_paths = {}
    for elb_name, value in elbs.iteritems():
        # find if sg_1 is behind current elb (this is important,because an instance doesnt talk out of an elb
        instance_behind_elb = 0
        if is_instances:
            # find which instance is behind lb
            instance_behind_elb = find_which_instance_is_behind_elb(elb_name, arguments.Instances[0][0], arguments.Instances[0][1])

        sg_1_to_elb = ports_a_can_talk_to_b(sg_1, value)
        elb_to_sg_1 = ports_a_can_talk_to_b(value, sg_1)
        sg_2_to_elb = ports_a_can_talk_to_b(sg_2, value)
        elb_to_sg_2 = ports_a_can_talk_to_b(value, sg_2)

        elb_paths[elb_name] = find_path(sg_1_to_elb, elb_to_sg_1, sg_2_to_elb, elb_to_sg_2, instance_behind_elb)

    return_data = { 'sg_1_to_2_direct': ports_1_to_2, 'sg_2_to_1_direct': ports_2_to_1, 'elbs': elb_paths}

    return return_data


# returns dict of what can talk to what, or -1 if all ports are open between the 2
def ports_a_can_talk_to_b(a, b):
    port_data = {}  # { protocol: set of ports }

    # For each egress permission
    for sg_out in a['ip_permissions_egress']:
        outbound_allowed = False
        all_egress = False
        # Check if there are even outbound permission to talk to other machine
        for ip in sg_out['IpRanges']:
            if ip['CidrIp'] == '0.0.0.0/0':
                outbound_allowed = True
                all_egress = True
                break
        for group in sg_out['UserIdGroupPairs']:
            if group['GroupId'] in b['group_ids']:
                outbound_allowed = True
                break

        # if a can access b, see if and where it has access
        if outbound_allowed:

            # For each ingress permission
            for sg_in in b['ip_permissions']:
                inbound_allowed = False
                for group in sg_in['UserIdGroupPairs']:
                    if group['GroupId'] in a['group_ids']:
                        inbound_allowed = True
                        break
                for ip in sg_in['IpRanges']:
                    if ip['CidrIp'] == '0.0.0.0/0':
                        inbound_allowed = True
                        break
                if not inbound_allowed:
                    continue

                # If allows all ingress
                if sg_out['IpProtocol'] == -1:
                    if all_egress:
                        return -1
                    else:
                        if sg_out['IpProtocol'] not in port_data:
                            port_data[sg_out['IpProtocol']] = set()
                        range_sg_out = [sg_out['FromPort']] if sg_out['FromPort'] == sg_out['ToPort'] else range(sg_out['FromPort'], sg_out['ToPort'])
                        port_data[sg_out['IpProtocol']] |= set(range_sg_out)

                elif all_egress:
                    if sg_in['IpProtocol'] not in port_data:
                        port_data[sg_in['IpProtocol']] = set()
                    range_sg_in = [sg_in['FromPort']] if sg_in['FromPort'] == sg_in['ToPort'] else range(sg_in['FromPort'], sg_in['ToPort'])
                    port_data[sg_in['IpProtocol']] |= set(range_sg_in)

                # If same protocol, or all protocols
                elif sg_in['IpProtocol'] == sg_out['IpProtocol']:
                    # If the port permissions match
                    range_sg_in = [sg_in['FromPort']] if sg_in['FromPort'] == sg_in['ToPort'] else range(sg_in['FromPort'], sg_in['ToPort'])
                    range_sg_out = [sg_out['FromPort']] if sg_out['FromPort'] == sg_out['ToPort'] else range(sg_out['FromPort'], sg_out['ToPort'])
                    intersection = set(set(range_sg_in) & set(range_sg_out))
                    if len(intersection) > 0:
                        if sg_out['IpProtocol'] not in port_data:
                            port_data[sg_out['IpProtocol']] = set()
                        port_data[sg_out['IpProtocol']] |= intersection

    return port_data


def main():

    if arguments.Security_Groups is None:
        instance1_sg = describe_sg(get_instance_sgs(arguments.Instances[0][0]))
        instance2_sg = describe_sg(get_instance_sgs(arguments.Instances[0][1]))
    else:
        instance1_sg = describe_sg([arguments.Security_Groups[0][0]])
        instance2_sg = describe_sg([arguments.Security_Groups[0][1]])

    results = compare_sg_rules(instance1_sg, instance2_sg)

    if is_instances:
        print_results(results, arguments.Instances[0][0], arguments.Instances[0][1])
    else:
        print_results(results, arguments.Security_Groups[0][0], arguments.Security_Groups[0][1])


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
    elb_client = boto3.client('elb', arguments.Region)

    is_instances = False
    if arguments.Security_Groups is None:
        is_instances = True
    print("")
    main()
    sys.exit(0)


