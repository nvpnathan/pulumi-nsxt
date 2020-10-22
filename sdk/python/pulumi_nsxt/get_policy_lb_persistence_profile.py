# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables

class GetPolicyLBPersistenceProfileResult:
    """
    A collection of values returned by getPolicyLBPersistenceProfile.
    """
    def __init__(__self__, description=None, display_name=None, id=None, path=None, type=None):
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
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        __self__.type = type
class AwaitableGetPolicyLBPersistenceProfileResult(GetPolicyLBPersistenceProfileResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPolicyLBPersistenceProfileResult(
            description=self.description,
            display_name=self.display_name,
            id=self.id,
            path=self.path,
            type=self.type)

def get_policy_lb_persistence_profile(description=None,display_name=None,id=None,type=None,opts=None):
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()


    __args__['description'] = description
    __args__['displayName'] = display_name
    __args__['id'] = id
    __args__['type'] = type
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = utilities.get_version()
    __ret__ = pulumi.runtime.invoke('nsxt:index/getPolicyLBPersistenceProfile:getPolicyLBPersistenceProfile', __args__, opts=opts).value

    return AwaitableGetPolicyLBPersistenceProfileResult(
        description=__ret__.get('description'),
        display_name=__ret__.get('displayName'),
        id=__ret__.get('id'),
        path=__ret__.get('path'),
        type=__ret__.get('type'))
