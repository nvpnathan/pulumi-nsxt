# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class PolicyIPPoolBlockSubnet(pulumi.CustomResource):
    auto_assign_gateway: pulumi.Output[bool]
    """
    If true, the first IP in the range will be reserved for gateway
    """
    block_path: pulumi.Output[str]
    """
    Policy path to the IP Block
    """
    description: pulumi.Output[str]
    """
    Description for this resource
    """
    display_name: pulumi.Output[str]
    """
    Display name for this resource
    """
    nsx_id: pulumi.Output[str]
    """
    NSX ID for this resource
    """
    path: pulumi.Output[str]
    """
    Policy path for this resource
    """
    pool_path: pulumi.Output[str]
    """
    Policy path to the IP Pool for this Subnet
    """
    revision: pulumi.Output[float]
    """
    The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
    changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
    operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
    """
    size: pulumi.Output[float]
    """
    Number of addresses
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    def __init__(__self__, resource_name, opts=None, auto_assign_gateway=None, block_path=None, description=None, display_name=None, nsx_id=None, pool_path=None, size=None, tags=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a PolicyIPPoolBlockSubnet resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[bool] auto_assign_gateway: If true, the first IP in the range will be reserved for gateway
        :param pulumi.Input[str] block_path: Policy path to the IP Block
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[str] pool_path: Policy path to the IP Pool for this Subnet
        :param pulumi.Input[float] size: Number of addresses
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

            __props__['auto_assign_gateway'] = auto_assign_gateway
            if block_path is None:
                raise TypeError("Missing required property 'block_path'")
            __props__['block_path'] = block_path
            __props__['description'] = description
            if display_name is None:
                raise TypeError("Missing required property 'display_name'")
            __props__['display_name'] = display_name
            __props__['nsx_id'] = nsx_id
            if pool_path is None:
                raise TypeError("Missing required property 'pool_path'")
            __props__['pool_path'] = pool_path
            if size is None:
                raise TypeError("Missing required property 'size'")
            __props__['size'] = size
            __props__['tags'] = tags
            __props__['path'] = None
            __props__['revision'] = None
        super(PolicyIPPoolBlockSubnet, __self__).__init__(
            'nsxt:index/policyIPPoolBlockSubnet:PolicyIPPoolBlockSubnet',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, auto_assign_gateway=None, block_path=None, description=None, display_name=None, nsx_id=None, path=None, pool_path=None, revision=None, size=None, tags=None):
        """
        Get an existing PolicyIPPoolBlockSubnet resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[bool] auto_assign_gateway: If true, the first IP in the range will be reserved for gateway
        :param pulumi.Input[str] block_path: Policy path to the IP Block
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[str] path: Policy path for this resource
        :param pulumi.Input[str] pool_path: Policy path to the IP Pool for this Subnet
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[float] size: Number of addresses
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["auto_assign_gateway"] = auto_assign_gateway
        __props__["block_path"] = block_path
        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["nsx_id"] = nsx_id
        __props__["path"] = path
        __props__["pool_path"] = pool_path
        __props__["revision"] = revision
        __props__["size"] = size
        __props__["tags"] = tags
        return PolicyIPPoolBlockSubnet(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop
