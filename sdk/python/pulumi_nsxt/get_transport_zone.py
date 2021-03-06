# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables

class GetTransportZoneResult:
    """
    A collection of values returned by getTransportZone.
    """
    def __init__(__self__, description=None, display_name=None, host_switch_name=None, id=None, transport_type=None):
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        __self__.description = description
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        __self__.display_name = display_name
        if host_switch_name and not isinstance(host_switch_name, str):
            raise TypeError("Expected argument 'host_switch_name' to be a str")
        __self__.host_switch_name = host_switch_name
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        __self__.id = id
        if transport_type and not isinstance(transport_type, str):
            raise TypeError("Expected argument 'transport_type' to be a str")
        __self__.transport_type = transport_type
class AwaitableGetTransportZoneResult(GetTransportZoneResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetTransportZoneResult(
            description=self.description,
            display_name=self.display_name,
            host_switch_name=self.host_switch_name,
            id=self.id,
            transport_type=self.transport_type)

def get_transport_zone(description=None,display_name=None,host_switch_name=None,id=None,transport_type=None,opts=None):
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()


    __args__['description'] = description
    __args__['displayName'] = display_name
    __args__['hostSwitchName'] = host_switch_name
    __args__['id'] = id
    __args__['transportType'] = transport_type
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = utilities.get_version()
    __ret__ = pulumi.runtime.invoke('nsxt:index/getTransportZone:getTransportZone', __args__, opts=opts).value

    return AwaitableGetTransportZoneResult(
        description=__ret__.get('description'),
        display_name=__ret__.get('displayName'),
        host_switch_name=__ret__.get('hostSwitchName'),
        id=__ret__.get('id'),
        transport_type=__ret__.get('transportType'))
