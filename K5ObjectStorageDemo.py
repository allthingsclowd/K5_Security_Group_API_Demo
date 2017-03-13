#!/usr/bin/python
""" Fujitsu K5 ObjectStorage Demo Application
    
    This script shows how to create a new object storage container in OpenStack Swift 
    that is publically available and then upload files to that container



Author: Graham Land
Date: 10/03/17
Twitter: @allthingsclowd
Github: https://github.com/allthingscloud
Blog: https://allthingscloud.eu


"""

import requests
import sys
import os
import datetime


def get_scoped_token(adminUser, adminPassword, contract, projectid, region):
    """Ket a K5 project scoped token

    Args:
        adminUser (TYPE): k5 username
        adminPassword (TYPE): K5 password
        contract (TYPE): K5 contract name
        projectid (TYPE): K5 project id to scope to
        region (TYPE): K5 region

    Returns:
        TYPE: K5 token object
    """
    identityURL = 'https://identity.' + region + \
        '.cloud.global.fujitsu.com/v3/auth/tokens'

    try:
        response = requests.post(identityURL,
                                 headers={'Content-Type': 'application/json',
                                          'Accept': 'application/json'},
                                 json={"auth":
                                         {"identity":
                                          {"methods": ["password"], "password":
                                           {"user":
                                           {"domain":
                                               {"name": contract},
                                            "name": adminUser,
                                            "password": adminPassword
                                            }}},
                                          "scope":
                                          {"project":
                                           {"id": projectid
                                            }}}})

        return response
    except:
        return 'Regional Project Token Scoping Failure'


# create a container
def create_new_storage_container(k5token, container_name):
    """
    Create a publically accessible k5 object storage container

    Args:
        container_name (TYPE): Description

    Returns:
        The URL to the new container
    """
    objectURL = unicode(get_endpoint(k5token, "objectstorage")) + '/' + unicode(container_name)
    print objectURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.put(objectURL,
                                 headers={'X-Auth-Token':token,'Content-Type': 'application/json','X-Container-Read': '.r:*'})

        return objectURL
    except:
        return ("\nUnexpected error:", sys.exc_info())

# download item in a container
def download_item_in_storage_container(k5token, container_name, object_name):
    """Download item from K5 object storage

    Args:
        k5token (TYPE): Description
        container_name (TYPE): Description
        object_name (TYPE): Description

    Returns:
        TYPE: Description
    """
    objectURL = unicode(get_endpoint(k5token, "objectstorage")) + '/' + unicode(container_name) + '/' + unicode(object_name)
    print objectURL
    token = k5token.headers['X-Subject-Token']

    try:
        response = requests.get(objectURL,
                                 headers={'X-Auth-Token':token,'Content-Type': 'application/json'})

        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())
        
# upload a file to a container
def upload_file_to_container(k5token, container_name, file_path, file_name):
    """Summary

    Args:
        container_name (TYPE): Description
        file_path (TYPE): Description

    Returns:
        TYPE: Description
    """
    try:
        uploadfile = open(file_path, 'rb')
        data = uploadfile.read()
        objectURL = unicode(get_endpoint(k5token, "objectstorage")) + '/' + unicode(container_name) + '/' + unicode(file_name)
        print objectURL
        token = k5token.headers['X-Subject-Token']

        response = requests.put(objectURL,
                                  data=data,
                                  headers={'X-Auth-Token':token,'Content-Type': 'application/octet-stream','X-Container-Read': '.r:*'})

        uploadfile.close
        return response
    except:
        return ("\nUnexpected error:", sys.exc_info())


def main():
    """Summary

    Returns:
        TYPE: Description
    """
    # Environment Variables
    adminUser = 'enter k5 username'
    adminPassword = 'enter k5 password'
    contract = 'enter contract name'
    demoProjectAid = 'enter target project'
    region = 'enter K5 target region'

    # Get a project scoped token
    k5token = get_scoped_token(adminUser, adminPassword, contract, demoProjectAid, region)
    
    # Create the new storage container called web-probe
    print create_new_storage_container(k5token, "web-probe")
    
    # Set the directory where the files are stored
    targetDirectory = "C:\some_path\web-probe"
    
    # Loop through all the files in the directory
    for filename in os.listdir(targetDirectory):
        targetFullPath = targetDirectory + "\\" + filename
        print targetFullPath
        # Upload the current file to the object storage container 
        print upload_file_to_container(k5token, "web-probe", targetFullPath, filename)


if __name__ == "__main__":
    main()