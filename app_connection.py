#!/usr/bin/env python
import argparse
import boto3
import json
import logging
import os
import sys
import traceback

ec2_client = boto3.client('ec2', 'us-east-1')


def get_instance_data(instance_id):
    try:
        response = ec2_client.describe_instances(
            InstanceIds=[instance_id]
        )
    except Exception as e:
        # Todo: Implement error handling
        pass

    return response.Reservations[0].Instances[0]


def main():
    return


if __name__ == "__main__":
    # Arguments
    parser = argparse.ArgumentParser(description='Checks if two machines in AWS have '
                                                 'permission to talk with each other.')

    instance_or_sg = parser.add_mutually_exclusive_group(required=True)
    instance_or_sg.add_argument('--instance_ids', action='append', dest='Instances', required=True,
                                nargs='2', help='ID of instances to check connectivity permissions between them.')
    instance_or_sg.add_argument('--security_group_ids', action='append', dest='Security_Group', required=True,
                                 nargs='2', help='ID of SGs to check connectivity permissions between them.')

    arguments = parser.parse_args()

    main(arguments)


