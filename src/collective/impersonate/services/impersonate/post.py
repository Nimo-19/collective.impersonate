from Acquisition import aq_inner
from Acquisition import aq_parent
from collective.impersonate.api.impersonate import impersonateUser
from plone import api
from plone.restapi.deserializer import json_body
from plone.restapi.services import Service
from Products.CMFCore.utils import getToolByName
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from zope.interface import alsoProvides

import plone.protect.interfaces


class Impersonate(Service):
    """Handles impersonation and returns a JSON web token (JWT)."""

    def reply(self):
        data = json_body(self.request)
        if "userid" not in data:
            self.request.response.setStatus(400)
            return {
                "error": {
                    "type": "Missing userid",
                    "message": "Login and password must be provided in body.",
                }
            }

        # Disable CSRF protection
        if "IDisableCSRFProtection" in dir(plone.protect.interfaces):
            alsoProvides(self.request, plone.protect.interfaces.IDisableCSRFProtection)

        userid = data["userid"]
        uf = self._find_userfolder(userid)

        # Also put the password in __ac_password on the request.
        # The post-login code in PlonePAS expects to find it there
        # when it calls the PAS updateCredentials plugin.
        if uf is not None:
            plugins = uf._getOb("plugins")
            authenticators = plugins.listPlugins(IAuthenticationPlugin)
            plugin = None
            for id_, authenticator in authenticators:
                if authenticator.meta_type == "JWT Authentication Plugin":
                    plugin = authenticator
                    break

            if plugin is None:
                self.request.response.setStatus(501)
                return {
                    "error": {
                        "type": "Login failed",
                        "message": "JWT authentication plugin not installed.",
                    }
                }

            user = api.user.get(username=userid)
        else:
            user = None

        if not user:
            self.request.response.setStatus(404)
            return {"error": {"type": "Invalid userid", "message": "Wrong userid"}}

        payload = {}
        payload["fullname"] = user.getProperty("fullname")

        impersonateUser(self.context, userid)
        return {"token": plugin.create_token(user.getId(), data=payload)}

    def _find_userfolder(self, userid):
        """Try to find a user folder that contains a user with the given
        userid.
        """
        uf_parent = aq_inner(self.context)
        info = None

        while not info:
            uf = getToolByName(uf_parent, "acl_users")
            if uf:
                info = uf._verifyUser(uf.plugins, login=userid)
            if uf_parent is self.context.getPhysicalRoot():
                break
            uf_parent = aq_parent(uf_parent)

        if info:
            return uf
