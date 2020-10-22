# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables

class GetPolicyEdgeNodeResult:
    """
    A collection of values returned by getPolicyEdgeNode.
    """
    def __init__(__self__, description=None, display_name=None, edge_cluster_path=None, id=None, member_index=None, path=None):
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        __self__.description = description
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        __self__.display_name = display_name
        if edge_cluster_path and not isinstance(edge_cluster_path, str):
            raise TypeError("Expected argument 'edge_cluster_path' to be a str")
        __self__.edge_cluster_path = edge_cluster_path
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        __self__.id = id
        if member_index and not isinstance(member_index, float):
            raise TypeError("Expected argument 'member_index' to be a float")
        __self__.member_index = member_index
        if path and not isinstance(path, str):
            raise TypeError("Expected argument 'path' to be a str")
        __self__.path = path
class AwaitableGetPolicyEdgeNodeResult(GetPolicyEdgeNodeResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetPolicyEdgeNodeResult(
            description=self.description,
            display_name=self.display_name,
            edge_cluster_path=self.edge_cluster_path,
            id=self.id,
            member_index=self.member_index,
            path=self.path)

def get_policy_edge_node(description=None,display_name=None,edge_cluster_path=None,id=None,member_index=None,opts=None):
    """
    Use this data source to access information about an existing resource.
    """
    __args__ = dict()


    __args__['description'] = description
    __args__['displayName'] = display_name
    __args__['edgeClusterPath'] = edge_cluster_path
    __args__['id'] = id
    __args__['memberIndex'] = member_index
    if opts is None:
        opts = pulumi.InvokeOptions()
    if opts.version is None:
        opts.version = utilities.get_version()
    __ret__ = pulumi.runtime.invoke('nsxt:index/getPolicyEdgeNode:getPolicyEdgeNode', __args__, opts=opts).value

    return AwaitableGetPolicyEdgeNodeResult(
        description=__ret__.get('description'),
        display_name=__ret__.get('displayName'),
        edge_cluster_path=__ret__.get('edgeClusterPath'),
        id=__ret__.get('id'),
        member_index=__ret__.get('memberIndex'),
        path=__ret__.get('path'))