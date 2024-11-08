import io
import json
import logging
import oci
import os
import requests
import base64
import re

from fdk import response

# Retrieve the values from environment variables
tenancy_ocid = os.environ.get("OCI_TENANCY_OCID")
user_ocid = os.environ.get("OCI_USER_OCID")
fingerprint = os.environ.get("OCI_FINGERPRINT")
private_key_file_location = os.environ.get("OCI_PRIVATE_KEY_FILE")
region = os.environ.get("OCI_REGION")

def handler(ctx, data: io.BytesIO = None):
    logger = logging.getLogger()
    logger.info("OpenSearch Ingestion function start")

    # Retrieving the OpenSearch configuration values
    try:
        cfg = dict(ctx.Config())
        apiEndpoint = cfg["openSearchAPIEndpoint"]
        username = cfg["openSearchUser"]
        password = cfg["openSearchPassword"]
        searchIndex = cfg["searchIndex"]
    except:
        logger.error('Missing configuration keys: openSearchAPIEndpoint, openSearchUser, openSearchPassword')
        raise

    try:
        body = json.loads(data.getvalue())
        bucket_name  = body["data"]["additionalDetails"]["bucketName"]
        object_name  = body["data"]["resourceName"]
        logger.info('Function invoked for bucket upload: ' + bucket_name)
    except (Exception, ValueError) as ex:
        logger.info('error parsing json payload: ' + str(ex))

    # Get the object data from Object Storage
    content = get_object(bucket_name, object_name)
    logger.info(content)

    logger.info("Processing the following updated data:")
    content = '[' + re.sub(r'\s+', '', content).replace("}{", "},{") + ']'
    logger.info(content)

    records = json.loads(content)

    openSearchData = ""
    for data in records:
        logger.info(data)

        json_data = {
            "ID": data["ID"],
            "PID": data["PID"],
            "NAME": data["NAME"],
            "BRAND": data["BRAND"],
            "IMAGE": data["IMAGE"],
            "PRICE": data["PRICE"],
            "CATEGORIES": data["CATEGORIES"],
            "POPULARITY": data["POPULARITY"],
            "DESCRIPTION": data["DESCRIPTION"],
            "STOCK_NUMBER": data["STOCK_NUMBER"],
            "UPDATED_TIMESTAMP": data["UPDATED_TIMESTAMP"]
        }
        json_string = json.dumps(json_data)

        openSearchData += f'{{"index":{{"_index":"{searchIndex}","_id":{data["PID"]}}}}}\n'
        openSearchData += json_string + "\n"

    logger.info("Final data inserted into OpenSearch:")
    logger.info(openSearchData)
    resp = opensearch_insert(apiEndpoint, username, password, searchIndex, openSearchData)
    logger.info(resp)

    return response.Response(
        ctx, response_data="Success...",
        headers={"Content-Type": "application/json"}
    )


def get_object(bucketName, objectName):
    signer = oci.auth.signers.get_resource_principals_signer()
    client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
    namespace = client.get_namespace().data
    try:
        print("Searching for bucket and object", flush=True)
        print("namespace:" + namespace, flush=True)
        object = client.get_object(namespace, bucketName, objectName)
        print("found object", flush=True)
        if object.status == 200:
            print("Success: The object " + objectName + " was retrieved with the content: ", flush=True)
        else:
            print("Failed: The object " + objectName + " could not be retrieved.")
    except Exception as e:
        print("Failed: " + str(e.message))
    return object.data.content.decode('utf-8')


def opensearch_insert(apiEndpoint, username, password, searchIndex, openSearchData):
    auth=(username, password)
    bulkinserturl = apiEndpoint + '/' + searchIndex + "/_bulk?pretty"
    headers = {'Content-Type': 'application/x-ndjson'}
    resp = requests.post(bulkinserturl, auth=auth, headers=headers, data=openSearchData)
    return resp.json()