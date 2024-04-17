#!/usr/bin/env python3

import os
import sys
import json
import requests
import kubernetes
from openshift.dynamic import DynamicClient, exceptions
from kubernetes.client import ApiClient


def authenticate(host, key):
    """Creates an OpenShift DynamicClient using a Kubernetes client config."""
    k8s_client = kubernetes.client.Configuration()

    k8s_client.host = host
    k8s_client.api_key = key
    k8s_client.verify_ssl = False

    setattr(k8s_client,
            'api_key',
            {'authorization': "Bearer {0}".format(k8s_client.api_key)})

    kubernetes.client.Configuration.set_default(k8s_client)
    return DynamicClient(kubernetes.client.ApiClient(k8s_client))


def update_managedclusters(client,bearer_token):
    """List active managed clusters."""
    infra_id=''
    cluster_id=''
    # archive_ocm_stale_clsuters(bearer_token)

    try:
        v1_spokes = client.resources.get(
            api_version='cluster.open-cluster-management.io/v1',
            kind='ManagedCluster')
        spokes = v1_spokes.get()["items"]

        for item in spokes:
            if item["metadata"]["labels"]["vendor"] == "OpenShift":
                if item["status"]["clusterClaims"] != None:
                    for claim in item["status"]["clusterClaims"]:  
                        if claim["name"] == "infrastructure.openshift.io" :
                            infra_id = json.loads(claim["value"])["infraName"]
                        if claim["name"] == "id.openshift.io" :
                            cluster_id = claim["value"]
                    if infra_id != '' and cluster_id != '':
                        update_ocm_displayName(cluster_id, infra_id, bearer_token)
    
    except Exception as e:
        print("Error")
        sys.exit(1)


def update_ocm_displayName(clusterID, infraID, bearer_token):
    """Updage ocm display name."""
    print(infraID)

    subID = get_ocm_subscription(clusterID,bearer_token)
    url = "https://api.openshift.com/api/accounts_mgmt/v1/subscriptions/" + subID
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        'Content-Type': 'application/json'
    }
    request_body = '{ "display_name": "0_'+ infraID +'" }'
    res = requests.patch(url, headers=headers, data=request_body).json()
    print(res)


def archive_ocm_stale_clsuters(bearer_token):
    """Archive stale clusters."""

    url = "https://api.openshift.com/api/accounts_mgmt/v1/subscriptions?search=creator.id%3D'1sDC9c5XHIV6FykHhxfxNJKkhTh'%20and%20status%3D'Stale'"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        'Content-Type': 'application/json'
    }
    request_body = '{ "status": "Archived" }'
    res = requests.get(url, headers=headers).json()
    if len(res["items"]) > 0:
        requests.patch(url, headers=headers, data=request_body).json()
        
    print(len(res["items"]))


def get_ocm_subscription(clusterID,bearer_token):
    subID = ''
    url = "https://api.openshift.com/api/accounts_mgmt/v1/subscriptions?search=creator.id%3D'1sDC9c5XHIV6FykHhxfxNJKkhTh'%20and%20status%3D'Active'"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        'Content-Type': 'application/json'
    }
    res = requests.get(url, headers=headers).json()
    for item in res["items"]:
        if item["external_cluster_id"] == clusterID:
            subID = item["id"]
            # print(item['id'])       
    return subID


def get_ocm_token():
    url = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    request_body = {
        "grant_type": "refresh_token",
        "client_id": "cloud-services",
        "refresh_token": get_env('OCM_TOKEN')
    }    
    res = requests.post(url, headers=headers, data=request_body).json()
    # print (res["access_token"]) 
    return res["access_token"]


def get_env(var):
    """Get varible from the contianer environment."""
    try:
        variable = os.environ.get(var)
    except KeyError as e:
        print('No environment variable named {}'.format(e))
        sys.exit(1)

    return variable


def get_hub_token(file='/var/run/secrets/kubernetes.io/serviceaccount/token'):
    """Get the ServiceAccount's token."""
    try:
        with open(file) as f:
            value = f.read()
    except FileNotFoundError as e:
        print("Failed to load token: {}".format(e))
        sys.exit(1)

    return value


def main():
    """Get the token from the enviroment, and query for pods."""
    hub_api = get_env('HOST')
    hub_token = get_hub_token()
    access_token = get_ocm_token()

    client = authenticate(hub_api, hub_token)
    update_managedclusters(client, access_token)


if __name__ == "__main__":
    sys.exit(main())
