# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class PolicyContextProfile(pulumi.CustomResource):
    app_ids: pulumi.Output[list]
    description: pulumi.Output[str]
    """
    Description for this resource
    """
    display_name: pulumi.Output[str]
    """
    Display name for this resource
    """
    domain_name: pulumi.Output[dict]
    nsx_id: pulumi.Output[str]
    """
    NSX ID for this resource
    """
    path: pulumi.Output[str]
    """
    Policy path for this resource
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
    url_category: pulumi.Output[dict]
    def __init__(__self__, resource_name, opts=None, app_ids=None, description=None, display_name=None, domain_name=None, nsx_id=None, tags=None, url_category=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a PolicyContextProfile resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **app_ids** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `isAlgType` (`pulumi.Input[bool]`)
          * `subAttribute` (`pulumi.Input[dict]`)
            * `cifsSmbVersions` (`pulumi.Input[list]`)
            * `tlsCipherSuites` (`pulumi.Input[list]`)
            * `tlsVersions` (`pulumi.Input[list]`)

          * `values` (`pulumi.Input[list]`)

        The **domain_name** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `values` (`pulumi.Input[list]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)

        The **url_category** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `values` (`pulumi.Input[list]`)
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

            __props__['app_ids'] = app_ids
            __props__['description'] = description
            if display_name is None:
                raise TypeError("Missing required property 'display_name'")
            __props__['display_name'] = display_name
            __props__['domain_name'] = domain_name
            __props__['nsx_id'] = nsx_id
            __props__['tags'] = tags
            __props__['url_category'] = url_category
            __props__['path'] = None
            __props__['revision'] = None
        super(PolicyContextProfile, __self__).__init__(
            'nsxt:index/policyContextProfile:PolicyContextProfile',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, app_ids=None, description=None, display_name=None, domain_name=None, nsx_id=None, path=None, revision=None, tags=None, url_category=None):
        """
        Get an existing PolicyContextProfile resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[str] path: Policy path for this resource
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **app_ids** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `isAlgType` (`pulumi.Input[bool]`)
          * `subAttribute` (`pulumi.Input[dict]`)
            * `cifsSmbVersions` (`pulumi.Input[list]`)
            * `tlsCipherSuites` (`pulumi.Input[list]`)
            * `tlsVersions` (`pulumi.Input[list]`)

          * `values` (`pulumi.Input[list]`)

        The **domain_name** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `values` (`pulumi.Input[list]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)

        The **url_category** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `values` (`pulumi.Input[list]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["app_ids"] = app_ids
        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["domain_name"] = domain_name
        __props__["nsx_id"] = nsx_id
        __props__["path"] = path
        __props__["revision"] = revision
        __props__["tags"] = tags
        __props__["url_category"] = url_category
        return PolicyContextProfile(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop
