from django.contrib.auth.models import User
# users
from django_prbac.models import Grant, Role

# Privileges


# groups


# grants
def create_rbac_role(role_name):
    Role.objects.create(name=role_name, slug=role_name, description='Role for django user: %s' % role_name)


def delete_rbac_role(role_name):
    Role.objects.get(name=role_name).delete()


def create_grant(grant_name):
    Role.objects.create(name=grant_name, slug=grant_name, description='Grant: %s' % grant_name)


def delete_grant(grant_name):
    Role.objects.get(name=grant_name).delete()


def create_role_grant(role=None, grant=None):
    roles = Role.objects.get(name=role)
    grants = Role.objects.get(name=grant)
    Grant.objects.create(from_role=roles, to_role=grants)

# do not work for UserRole OneToOneField
def create_user_role(username=None, rolename=None):
    users = User.objects.get(username=username)
    roles = Role.objects.get(name=rolename)
    MyUserRole.objects.create(user=users, role=roles)
