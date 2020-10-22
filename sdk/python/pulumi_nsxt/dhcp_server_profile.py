# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class DHCPServerProfile(pulumi.CustomResource):
    description: pulumi.Output[str]
    """
    Description of this resource
    """
    display_name: pulumi.Output[str]
    """
    The display name of this resource. Defaults to ID if not set
    """
    edge_cluster_id: pulumi.Output[str]
    """
    Edge cluster uuid
    """
    edge_cluster_member_indexes: pulumi.Output[list]
    """
    Edge nodes from the given cluster
    """
    revision: pulumi.Output[float]
    """
    The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
    changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
    operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    def __init__(__self__, resource_name, opts=None, description=None, display_name=None, edge_cluster_id=None, edge_cluster_member_indexes=None, tags=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a DHCPServerProfile resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[str] edge_cluster_id: Edge cluster uuid
        :param pulumi.Input[list] edge_cluster_member_indexes: Edge nodes from the given cluster
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        if __name__ is not None:
            warnings.warn("explicit use of __name__ is deprecated", DeprecationWarning)
            resource_name = __name__
        if __opts__ is not None:
            warnings.warn("explicit use of __opts__ is deprecated, use 'opts' instead", DeprecationWarning)
            opts = __opts__
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = dict()

            __props__['description'] = description
            __props__['display_name'] = display_name
            if edge_cluster_id is None:
                raise TypeError("Missing required property 'edge_cluster_id'")
            __props__['edge_cluster_id'] = edge_cluster_id
            __props__['edge_cluster_member_indexes'] = edge_cluster_member_indexes
            __props__['tags'] = tags
            __props__['revision'] = None
        super(DHCPServerProfile, __self__).__init__(
            'nsxt:index/dHCPServerProfile:DHCPServerProfile',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, description=None, display_name=None, edge_cluster_id=None, edge_cluster_member_indexes=None, revision=None, tags=None):
        """
        Get an existing DHCPServerProfile resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[str] edge_cluster_id: Edge cluster uuid
        :param pulumi.Input[list] edge_cluster_member_indexes: Edge nodes from the given cluster
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["edge_cluster_id"] = edge_cluster_id
        __props__["edge_cluster_member_indexes"] = edge_cluster_member_indexes
        __props__["revision"] = revision
        __props__["tags"] = tags
        return DHCPServerProfile(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop
