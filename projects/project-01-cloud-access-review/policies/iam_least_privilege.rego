package iam.access

default allow := false

deny contains msg if {
  some user in input.users
  policy := user.attached_policies[_]
  policy == "AdministratorAccess"
  msg := sprintf("User %s is over-permissioned: AdministratorAccess attached", [user.name])
}

allow if {
  count(deny) == 0
}