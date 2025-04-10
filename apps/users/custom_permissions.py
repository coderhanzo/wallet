from rest_framework import permissions
from .models import User


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.roles in [User.Roles.ADMIN, User.Roles.IMAM]


class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.roles == User.Roles.ADMIN


class IsImam(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.roles == User.Roles.IMAM


class IsAssociate(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.roles == User.Roles.ASSOCIATE
