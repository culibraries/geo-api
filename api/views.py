__author__ = 'mstacy'
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework import serializers, generics
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
#from .models import AuthtokenToken, AuthUser
from django.contrib.auth.decorators import login_required
from hashlib import md5
import os,json,requests
#from rest_framework import viewsets
#from rest_framework.permissions import AllowAny
#from .permissions import IsStaffOrTargetUser
from rest_framework.parsers import JSONParser,MultiPartParser,FormParser,FileUploadParser
from rest_framework.renderers import BrowsableAPIRenderer, JSONPRenderer,JSONRenderer,XMLRenderer,YAMLRenderer
from rest_framework.authentication import SessionAuthentication, TokenAuthentication

#Login required mixin
class LoginRequiredMixin(object):
    @classmethod
    def as_view(cls, **initkwargs):
        view = super(LoginRequiredMixin, cls).as_view(**initkwargs)
        return login_required(view)



class APIRoot(APIView):
    permission_classes = ( IsAuthenticatedOrReadOnly,)

    def get(self, request,format=None):
        return Response({
            'Queue': {'Tasks': reverse('queue-main', request=request),
                      'Tasks History': reverse('queue-user-tasks',request=request)},
            'Catalog': {'Data Source':reverse('catalog-list',request=request)},
            'Data Store': {'Mongo':reverse('data-list',request=request)},
            'User Profile': {'User':reverse('user-list',request=request)}
        })

class UserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=50)
    last_name = serializers.CharField(max_length=50)

#LoginRequiredMixin,
class UserProfile(APIView):
    authentication_classes = (SessionAuthentication, TokenAuthentication)
    permission_classes = ( IsAuthenticated,)
    serializer_class = UserSerializer
    fields = ('username', 'first_name', 'last_name', 'email')
    model = User
    def get(self,request,id=None,format=None):
        data = User.objects.get(pk=self.request.user.id)
        serializer = self.serializer_class(data,context={'request':request})
        tok = Token.objects.get_or_create(user=self.request.user)
        rdata = serializer.data
        rdata['name'] = data.get_full_name()
        rdata['gravator_url']="{0}://www.gravatar.com/avatar/{1}".format(request.scheme,md5(rdata['email'].strip(' \t\n\r')).hexdigest())
        rdata['auth-token']= str(tok[0])
        return Response(rdata)
    def post(self,request,format=None):
        user = User.objects.get(pk=self.request.user.id)
        password = request.DATA.get('password', None)
        if password:
            user.set_password(password)
            user.save()
            data = {"password":"Successfully Updated"}
            return Response(data)
        auth_tok  = request.DATA.get('auth-token', None)
        if str(auth_tok).lower()=="update":
            tok = Token.objects.get(user=user)
            tok.delete()
            tok = Token.objects.get_or_create(user=self.request.user)
            data = {"auth-token":str(tok[0])}
            return Response(data)
        else:
            user.first_name =request.DATA.get('first_name', user.first_name)
            user.last_name = request.DATA.get('last_name', user.last_name)
            user.email = request.DATA.get('email', user.email)
            serializer = self.serializer_class(user,context={'request':request})
            data = serializer.data
            user.save()
            tok = Token.objects.get_or_create(user=self.request.user)
            data['name'] = user.get_full_name()
            data['gravator_url']="{0}://www.gravatar.com/avatar/{1}".format(request.scheme,md5(data['email'].strip(' \t\n\r')).hexdigest())
            data['auth-token']= str(tok[0])
            return Response(data)

from rest_framework import permissions
class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the snippet.
        return obj.owner == request.user

class fileDataUploadView(APIView):
        permission_classes =(IsAuthenticated,)
        #parser_classes = (MultiPartParser, FormParser,FileUploadParser,)
        parser_classes = (FileUploadParser,)
        renderer_classes = (JSONRenderer,)

        def post(self, request, uploadDirectory="/data/file_upload",format=None):
                #check if uploadDirectory exists
                if not os.path.isdir(uploadDirectory):
                    os.makedirs(uploadDirectory)
                results=[]
                #upload files submitted
                for key,value in request.FILES.iteritems():
                    result={}
                    filename= value.name
                    local_file = "{0}/{1}".format(uploadDirectory,filename)
                    self.handle_file_upload(request.FILES[key],local_file)
                    result[key]=local_file
                    if request.DATA.get("callback",None):
                        req = self.callback_task(request,local_file)
                        try:
                            result['callback']={"status":req.status_code,"response":req.json()}
                        except:
                            result['callback']={"status":req.status_code,"response":req.text}
                    results.append(result)
                return Response(results)


        def handle_file_upload(self,f,filename):
            if f.multiple_chunks():
                    with open(filename, 'wb+') as temp_file:
                            for chunk in f.chunks():
                                    temp_file.write(chunk)
            else:
                    with open(filename, 'wb+') as temp_file:
                            temp_file.write(f.read())

        def callback_task(request,local_file):
            #Get Token for task submission
            tok = Token.objects.get_or_create(user=request.user)
            headers = {'Authorization':'Token {0}'.format(str(tok[0])),'Content-Type':'application/json'}
            queue = request.DATA.get("queue","celery")
            tags = request.DATA.get("tags",'') # tags is a comma separated string; Converted to list
            tags= tags.split(',')
            taskname = request.DATA.get("callback")
            payload={"function": taskname,"queue": queue,"args":[local_file,request.DATA],"kwargs":{},"tags":tags}
            components = request.build_absolute_uri().split('/')
            hostname = os.environ.get("api_hostname", components[2])
            url = "{0}//{1}/api/queue/run/{2}/.json".format(components[0],hostname,taskname)
            return requests.post(url,data=json.dumps(payload),headers=headers)
