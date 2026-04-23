from plone import api


def impersonateUser(context, user_id):
    if not api.user.get(user_id):
        return

    context.acl_users.session._setupSession(user_id, context.REQUEST.RESPONSE)

    pass
