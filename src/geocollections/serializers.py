from dynamic_rest.serializers import DynamicModelSerializer
from dynamic_rest.fields.fields import DynamicRelationField

from geonode.base.api.serializers import GroupProfileSerializer, ResourceBaseSerializer

from .models import Geocollection


class GeocollectionSerializer(DynamicModelSerializer):

    class Meta:
        model = Geocollection
        name = 'geocollection'
        fields = (
            'pk', 'name', 'group', 'resources'
        )

    group = DynamicRelationField(GroupProfileSerializer, embed=True, many=False)
    resources = DynamicRelationField(ResourceBaseSerializer, embed=True, many=True)
