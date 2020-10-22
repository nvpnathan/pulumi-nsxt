# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class LBService(pulumi.CustomResource):
    description: pulumi.Output[str]
    """
    Description of this resource
    """
    display_name: pulumi.Output[str]
    """
    The display name of this resource. Defaults to ID if not set
    """
    enabled: pulumi.Output[bool]
    """
    Whether the load balancer service is enabled
    """
    error_log_level: pulumi.Output[str]
    """
    Load balancer engine writes information about encountered issues of different severity levels to the error log. This
    setting is used to define the severity level of the error log
    """
    logical_router_id: pulumi.Output[str]
    """
    Logical Tier1 Router to which the Load Balancer is to be attached
    """
    revision: pulumi.Output[float]
    """
    The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
    changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
    operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
    """
    size: pulumi.Output[str]
    """
    Size of load balancer service
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    virtual_server_ids: pulumi.Output[list]
    """
    Virtual servers associated with this Load Balancer
    """
    def __init__(__self__, resource_name, opts=None, description=None, display_name=None, enabled=None, error_log_level=None, logical_router_id=None, size=None, tags=None, virtual_server_ids=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a LBService resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[bool] enabled: Whether the load balancer service is enabled
        :param pulumi.Input[str] error_log_level: Load balancer engine writes information about encountered issues of different severity levels to the error log. This
               setting is used to define the severity level of the error log
        :param pulumi.Input[str] logical_router_id: Logical Tier1 Router to which the Load Balancer is to be attached
        :param pulumi.Input[str] size: Size of load balancer service
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[list] virtual_server_ids: Virtual servers associated with this Load Balancer

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
            __props__['enabled'] = enabled
            __props__['error_log_level'] = error_log_level
            if logical_router_id is None:
                raise TypeError("Missing required property 'logical_router_id'")
            __props__['logical_router_id'] = logical_router_id
            __props__['size'] = size
            __props__['tags'] = tags
            __props__['virtual_server_ids'] = virtual_server_ids
            __props__['revision'] = None
        super(LBService, __self__).__init__(
            'nsxt:index/lBService:LBService',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, description=None, display_name=None, enabled=None, error_log_level=None, logical_router_id=None, revision=None, size=None, tags=None, virtual_server_ids=None):
        """
        Get an existing LBService resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[bool] enabled: Whether the load balancer service is enabled
        :param pulumi.Input[str] error_log_level: Load balancer engine writes information about encountered issues of different severity levels to the error log. This
               setting is used to define the severity level of the error log
        :param pulumi.Input[str] logical_router_id: Logical Tier1 Router to which the Load Balancer is to be attached
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[str] size: Size of load balancer service
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[list] virtual_server_ids: Virtual servers associated with this Load Balancer

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["enabled"] = enabled
        __props__["error_log_level"] = error_log_level
        __props__["logical_router_id"] = logical_router_id
        __props__["revision"] = revision
        __props__["size"] = size
        __props__["tags"] = tags
        __props__["virtual_server_ids"] = virtual_server_ids
        return LBService(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop