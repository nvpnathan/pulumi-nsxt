# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables

class GetPolicyGatewayQOSProfileResult:
    """
    A collection of values returned by getPolicyGatewayQOSProfile.
    """
    def __init__(__self__, description=None, display_name=None, id=None, path=None):
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        __self__.description = description
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        __self__.display_name = display_name
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        __self__.id = id
        if path and not isinstance(path, str):
            raise TypeError("Expected argument 'path' to be a str")
        __self__.path = path
class AwaitableGetPolicyGatewayQOSProfileResult(GetPolicyGatewayQOSProfileResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPolicyGatewayQOSProfileResult(
            description=self.description,
            display_name=self.display_name,
            id=self.id,
            path=self.path)

def get_policy_gateway_qos_profile(description=None,display_name=None,id=None,opts=None):
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()


    __args__['description'] = description
    __args__['displayName'] = display_name
    __args__['id'] = id
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = utilities.get_version()
    __ret__ = pulumi.runtime.invoke('nsxt:index/getPolicyGatewayQOSProfile:getPolicyGatewayQOSProfile', __args__, opts=opts).value

    return AwaitableGetPolicyGatewayQOSProfileResult(
        description=__ret__.get('description'),
        display_name=__ret__.get('displayName'),
        id=__ret__.get('id'),
        path=__ret__.get('path'))
