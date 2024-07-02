#!/usr/bin/env python3

import os
import sys
import re
import json
import base64
import requests
import kubernetes 
from kubernetes import client, config
from openshift.dynamic import DynamicClient, exceptions
from kubernetes.client import ApiClient


def authenticate():
    # Check if code is running in OpenShift
    if os.getenv('KUBERNETES_SERVICE_HOST'):
        config.load_incluster_config()
        file_token = open(
            "/run/secrets/kubernetes.io/serviceaccount/token", "r"
        )
        if file_token.mode == "r":
            token = file_token.read()
            print("token: %s\n" %(token))
    else:
        config.load_kube_config()    

    # Create a client config
    k8s_client = config.new_client_from_config()
    dyn_client = DynamicClient(k8s_client)
    return dyn_client   
    

    # """Creates an OpenShift DynamicClient using a Kubernetes client config."""
    # k8s_client = kubernetes.client.Configuration()

    # k8s_client.host = host
    # # k8s_client.api_key = key
    # k8s_client.verify_ssl = False

    # setattr(k8s_client,
    #         'api_key',
    #         {'authorization': "Bearer {0}".format(key)})

    # kubernetes.client.Configuration.set_default(k8s_client)
    # return DynamicClient(kubernetes.client.api_client.ApiClient(k8s_client))


def update_managedclusters(client,bearer_token):
    """Update ocm subscriptons of managed clusters."""

    infra_id = ''
    cluster_id = ''
    platform = ''
    region = 'region'

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
                        if claim["name"] == "platform.open-cluster-management.io" :
                            platform = claim["value"].lower()
                        if claim["name"] == "region.open-cluster-management.io" :
                            region = claim["value"]                                                      
                    if infra_id != '' and cluster_id != '':
                        update_ocm_displayName(cluster_id, infra_id, platform, region, bearer_token)
    except Exception as e:
        print(e)
        sys.exit(1)


def update_ocm_displayName(clusterID, infraID, platform, region, token):
    """Updage ocm subscription display name."""
    print("cluster infraID: {} - platform: {} - region: {}".format(infraID,platform,region))

    subID = get_ocm_subscription(clusterID,token)
    if subID != '':
        url = "https://api.openshift.com/api/accounts_mgmt/v1/subscriptions/" + subID
        headers = {
            "Authorization": f"Bearer {token}",
            'Content-Type': 'application/json'
        }
        res = requests.get(url, headers=headers).json()
        # print(re.match('[0-1]_+', res["display_name"]))
        if re.match('[0-1]_+', res["display_name"]) == None:
            request_body = '{ "display_name": "0_'+ infraID + '_' + platform + '_' + region + '"}'
            post = requests.patch(url, headers=headers, data=request_body).json()
            print("update ocm subscription display name: {}".format(post["display_name"]))
        else:
            print("ocm subscription display name: {}".format(res["display_name"]))


def archive_ocm_stale_clusters(bearer_token):
    """Archive stale clusters."""

    url = "https://api.openshift.com/api/accounts_mgmt/v1/subscriptions?search=creator.id%3D%271sDC9c5XHIV6FykHhxfxNJKkhTh%27%20and%20status%3D%27Stale%27"
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
    url = f"https://api.openshift.com/api/accounts_mgmt/v1/subscriptions?search=creator.id%3D%271sDC9c5XHIV6FykHhxfxNJKkhTh%27%20and%20external_cluster_id%3D%27{clusterID}%27"
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        'Content-Type': 'application/json'
    }
    res = requests.get(url, headers=headers).json()
    for item in res["items"]:
        if item["external_cluster_id"] == clusterID:
            subID = item["id"]     
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


def get_credentials(client):
    """List the credentials with label."""

    try:
        v1_secrets = client.resources.get(
            api_version='v1',
            kind='Secret')
        secrets = v1_secrets.get(label_selector='cluster.open-cluster-management.io/credentials=')
    except Exception as e:
        print("Error getting secrets with credentials label")
        sys.exit(1)

    # print(secrets.items)
    return secrets


def get_global_pull_secret(client):
    """Get OCP global pull secret."""

    try:
        v1_secrets = client.resources.get(
            api_version='v1',
            kind='Secret')
        secrets = v1_secrets.get(name="pull-secret",namespace="openshift-config")
    except Exception as e:
        print("Error getting secrets with credentials label")
        sys.exit(1)

    # print(base64.b64decode(secrets.data[".dockerconfigjson"]))
    return secrets.data[".dockerconfigjson"] 


def update_creds_pull_secret(client):
    """Update creds pull secret."""

    creds = get_credentials(client)
    pull_secret = get_global_pull_secret(client)   
    v1_secrets = client.resources.get(
        api_version='v1',
        kind='Secret')

    if len(creds["items"]) > 0:
        for cred in creds["items"]:
            if cred.data.pullSecret != None:
                body = {
                    'data': {
                        'pullSecret': '{}'.format(pull_secret),
                    }
                }      
                res = v1_secrets.patch(name=cred.metadata.name,namespace=cred.metadata.namespace,body=body)
                print(res.metadata.name, res.metadata.managedFields[len(res.metadata.managedFields)-1], sep='\n')
            else:
                print("{} has no pull secret".format(cred.metadata.name))


def main():
    # hub_api = get_env('HOST')
    # hub_token = get_hub_token()
    access_token = get_ocm_token()

    # client = authenticate(hub_api, hub_token)
    client = authenticate()
    update_creds_pull_secret(client)
    update_managedclusters(client, access_token)


if __name__ == "__main__":
    sys.exit(main())
