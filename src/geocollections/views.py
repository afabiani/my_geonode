import json
import logging
import traceback

from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import DetailView
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import PermissionRequiredMixin

from dynamic_rest.viewsets import DynamicModelViewSet
from dynamic_rest.filters import DynamicFilterBackend, DynamicSortingFilter

from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from oauth2_provider.contrib.rest_framework import OAuth2Authentication

from geonode.base.api.pagination import GeoNodeApiPagination


from .models import Geocollection
from .serializers import GeocollectionSerializer
from .permissions import GeocollectionPermissionsFilter

logger = logging.getLogger(__name__)


class GeocollectionViewSet(DynamicModelViewSet):
    """
    API endpoint that allows geocollections to be viewed or edited.
    """
    authentication_classes = [SessionAuthentication, BasicAuthentication, OAuth2Authentication]
    permission_classes = [IsAuthenticatedOrReadOnly, ]
    filter_backends = [
        DynamicFilterBackend, DynamicSortingFilter,
        GeocollectionPermissionsFilter
    ]
    queryset = Geocollection.objects.all()
    serializer_class = GeocollectionSerializer
    pagination_class = GeoNodeApiPagination


class GeocollectionDetail(PermissionRequiredMixin, DetailView):

    model = Geocollection

    def has_permission(self):
        return self.request.user.has_perm('access_geocollection', self.get_object())

def geocollection_permissions(request, collection_slug):
    geocollection = Geocollection.objects.get(slug=collection_slug)
    user = request.user

    if not user.is_superuser:
        raise PermissionDenied

    def dump_perm_spec(perm_spec):
        json_perm_spec = {"users": {}, "groups": {}}
        for item in perm_spec.get("users"):
            json_perm_spec["users"][item.username] = perm_spec.get("users").get(item)
        for item in perm_spec.get("groups"):
            json_perm_spec["groups"][str(item)] = perm_spec.get("groups").get(item)
        return json.dumps(json_perm_spec, indent=2)

    if request.method == 'GET':
        _perm_spec = dump_perm_spec(geocollection.get_all_level_info())
        return render(request, 'geocollections/geocollection_permissions.html', context={'object': geocollection, 'json_perm_spec': _perm_spec})

    elif request.method == 'POST':
        success = True
        message = "Permissions successfully updated!"
        try:
            perm_spec = json.loads(request.POST.get('perm_spec'))
            logger.info(f" ---- setting perm_spec: {perm_spec}")
            geocollection.set_permissions(perm_spec)

            return HttpResponse(
                json.dumps({'success': success, 'message': message}),
                status=200,
                content_type='text/plain'
            )
        except Exception as e:
            traceback.print_exc()
            logger.exception(e)
            success = False
            message = f"Error updating permissions :(... error: {e}"
            return HttpResponse(
                json.dumps({'success': success, 'message': message}),
                status=500,
                content_type='text/plain'
            )
