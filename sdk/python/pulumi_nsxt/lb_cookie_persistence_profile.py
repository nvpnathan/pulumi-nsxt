# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class LBCookiePersistenceProfile(pulumi.CustomResource):
    cookie_fallback: pulumi.Output[bool]
    """
    A boolean flag which reflects whether once the server points by this cookie is down, a new server is selected, or the
    requests will be rejected
    """
    cookie_garble: pulumi.Output[bool]
    """
    A boolean flag which reflects whether the cookie value (server IP and port) would be encrypted or in plain text
    """
    cookie_mode: pulumi.Output[str]
    """
    The cookie persistence mode
    """
    cookie_name: pulumi.Output[str]
    """
    The name of the cookie
    """
    description: pulumi.Output[str]
    """
    Description of this resource
    """
    display_name: pulumi.Output[str]
    """
    The display name of this resource. Defaults to ID if not set
    """
    insert_mode_params: pulumi.Output[dict]
    """
    Additional parameters for the INSERT cookie mode

      * `cookieDomain` (`str`)
      * `cookieExpiryType` (`str`)
      * `cookiePath` (`str`)
      * `maxIdleTime` (`float`)
      * `maxLifeTime` (`float`)
    """
    persistence_shared: pulumi.Output[bool]
    """
    A boolean flag which reflects whether the cookie persistence is private or shared
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
    def __init__(__self__, resource_name, opts=None, cookie_fallback=None, cookie_garble=None, cookie_mode=None, cookie_name=None, description=None, display_name=None, insert_mode_params=None, persistence_shared=None, tags=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a LBCookiePersistenceProfile resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[bool] cookie_fallback: A boolean flag which reflects whether once the server points by this cookie is down, a new server is selected, or the
               requests will be rejected
        :param pulumi.Input[bool] cookie_garble: A boolean flag which reflects whether the cookie value (server IP and port) would be encrypted or in plain text
        :param pulumi.Input[str] cookie_mode: The cookie persistence mode
        :param pulumi.Input[str] cookie_name: The name of the cookie
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[dict] insert_mode_params: Additional parameters for the INSERT cookie mode
        :param pulumi.Input[bool] persistence_shared: A boolean flag which reflects whether the cookie persistence is private or shared
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **insert_mode_params** object supports the following:

          * `cookieDomain` (`pulumi.Input[str]`)
          * `cookieExpiryType` (`pulumi.Input[str]`)
          * `cookiePath` (`pulumi.Input[str]`)
          * `maxIdleTime` (`pulumi.Input[float]`)
          * `maxLifeTime` (`pulumi.Input[float]`)

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

            __props__['cookie_fallback'] = cookie_fallback
            __props__['cookie_garble'] = cookie_garble
            __props__['cookie_mode'] = cookie_mode
            if cookie_name is None:
                raise TypeError("Missing required property 'cookie_name'")
            __props__['cookie_name'] = cookie_name
            __props__['description'] = description
            __props__['display_name'] = display_name
            __props__['insert_mode_params'] = insert_mode_params
            __props__['persistence_shared'] = persistence_shared
            __props__['tags'] = tags
            __props__['revision'] = None
        super(LBCookiePersistenceProfile, __self__).__init__(
            'nsxt:index/lBCookiePersistenceProfile:LBCookiePersistenceProfile',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, cookie_fallback=None, cookie_garble=None, cookie_mode=None, cookie_name=None, description=None, display_name=None, insert_mode_params=None, persistence_shared=None, revision=None, tags=None):
        """
        Get an existing LBCookiePersistenceProfile resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[bool] cookie_fallback: A boolean flag which reflects whether once the server points by this cookie is down, a new server is selected, or the
               requests will be rejected
        :param pulumi.Input[bool] cookie_garble: A boolean flag which reflects whether the cookie value (server IP and port) would be encrypted or in plain text
        :param pulumi.Input[str] cookie_mode: The cookie persistence mode
        :param pulumi.Input[str] cookie_name: The name of the cookie
        :param pulumi.Input[str] description: Description of this resource
        :param pulumi.Input[str] display_name: The display name of this resource. Defaults to ID if not set
        :param pulumi.Input[dict] insert_mode_params: Additional parameters for the INSERT cookie mode
        :param pulumi.Input[bool] persistence_shared: A boolean flag which reflects whether the cookie persistence is private or shared
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **insert_mode_params** object supports the following:

          * `cookieDomain` (`pulumi.Input[str]`)
          * `cookieExpiryType` (`pulumi.Input[str]`)
          * `cookiePath` (`pulumi.Input[str]`)
          * `maxIdleTime` (`pulumi.Input[float]`)
          * `maxLifeTime` (`pulumi.Input[float]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["cookie_fallback"] = cookie_fallback
        __props__["cookie_garble"] = cookie_garble
        __props__["cookie_mode"] = cookie_mode
        __props__["cookie_name"] = cookie_name
        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["insert_mode_params"] = insert_mode_params
        __props__["persistence_shared"] = persistence_shared
        __props__["revision"] = revision
        __props__["tags"] = tags
        return LBCookiePersistenceProfile(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop
