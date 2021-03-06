# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables

class GetPolicySegmentRealizationResult:
    """
    A collection of values returned by getPolicySegmentRealization.
    """
    def __init__(__self__, id=None, network_name=None, path=None, state=None):
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        __self__.id = id
        if network_name and not isinstance(network_name, str):
            raise TypeError("Expected argument 'network_name' to be a str")
        __self__.network_name = network_name
        if path and not isinstance(path, str):
            raise TypeError("Expected argument 'path' to be a str")
        __self__.path = path
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        __self__.state = state
class AwaitableGetPolicySegmentRealizationResult(GetPolicySegmentRealizationResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPolicySegmentRealizationResult(
            id=self.id,
            network_name=self.network_name,
            path=self.path,
            state=self.state)

def get_policy_segment_realization(id=None,path=None,opts=None):
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()


    __args__['id'] = id
    __args__['path'] = path
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = utilities.get_version()
    __ret__ = pulumi.runtime.invoke('nsxt:index/getPolicySegmentRealization:getPolicySegmentRealization', __args__, opts=opts).value

    return AwaitableGetPolicySegmentRealizationResult(
        id=__ret__.get('id'),
        network_name=__ret__.get('networkName'),
        path=__ret__.get('path'),
        state=__ret__.get('state'))
