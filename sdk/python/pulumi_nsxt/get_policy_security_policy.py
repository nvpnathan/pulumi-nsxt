# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables

class GetPolicySecurityPolicyResult:
    """
    A collection of values returned by getPolicySecurityPolicy.
    """
    def __init__(__self__, category=None, description=None, display_name=None, domain=None, id=None, is_default=None, path=None):
        if category and not isinstance(category, str):
            raise TypeError("Expected argument 'category' to be a str")
        __self__.category = category
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        __self__.description = description
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        __self__.display_name = display_name
        if domain and not isinstance(domain, str):
            raise TypeError("Expected argument 'domain' to be a str")
        __self__.domain = domain
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        __self__.id = id
        if is_default and not isinstance(is_default, bool):
            raise TypeError("Expected argument 'is_default' to be a bool")
        __self__.is_default = is_default
        if path and not isinstance(path, str):
            raise TypeError("Expected argument 'path' to be a str")
        __self__.path = path
class AwaitableGetPolicySecurityPolicyResult(GetPolicySecurityPolicyResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPolicySecurityPolicyResult(
            category=self.category,
            description=self.description,
            display_name=self.display_name,
            domain=self.domain,
            id=self.id,
            is_default=self.is_default,
            path=self.path)

def get_policy_security_policy(category=None,description=None,display_name=None,domain=None,id=None,is_default=None,opts=None):
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()


    __args__['category'] = category
    __args__['description'] = description
    __args__['displayName'] = display_name
    __args__['domain'] = domain
    __args__['id'] = id
    __args__['isDefault'] = is_default
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = utilities.get_version()
    __ret__ = pulumi.runtime.invoke('nsxt:index/getPolicySecurityPolicy:getPolicySecurityPolicy', __args__, opts=opts).value

    return AwaitableGetPolicySecurityPolicyResult(
        category=__ret__.get('category'),
        description=__ret__.get('description'),
        display_name=__ret__.get('displayName'),
        domain=__ret__.get('domain'),
        id=__ret__.get('id'),
        is_default=__ret__.get('isDefault'),
        path=__ret__.get('path'))
