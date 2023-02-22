package authz

import future.keywords.if
import future.keywords.in
import data.rbac as rbac

default allow := false

allow if {
    user := input.user
    permission := "print_something"
    user_has_permission(user, permission)
}

user_has_permission(user, permission) := true if {
    rbac.users[user_id].name == user
    some user_role in rbac.users_roles
    [user_id, role_id] = user_role
    some role_permission in rbac.roles_permissions
    [role_id, permission_id] = role_permission
    rbac.permissions[permission_id].name == permission
}

# user_has_permission(user, permission) := true if {
#     rbac.users[user_id].name == user
#     users_roles := to_set(rbac.users_roles)
#     users_roles[[user_id, role_id]]
#     roles_permissions := to_set(rbac.roles_permissions)
#     roles_permissions[[role_id, permission_id] ]
#     rbac.permissions[permission_id].name == permission
# }

# to_set(arr) := a_set if {
#     a_set := {x | x := arr[_]}
# }