import string
from datetime import datetime
from uuid import uuid4
from django.http import JsonResponse
from rest_framework.views import APIView
from google.cloud import storage
from google.oauth2 import service_account
import tempfile

BUCKET = 'mumbai-dev'


class UploadService(APIView):
    def post(self, request):
        file = request.FILES['file']
        name = file.name
        extension = name.split(".")[-1]
        random = id_generator(4) + '-' + id_generator(8)
        path = random + "." + extension
        try:
            # uploaded = file.save(path)
            uploaded = upload_gcp(file, path)
        except Exception as e:
            print(e)
            return JsonResponse({'status': False, 'message': 'error', 'data': {}}, status=400)

        return JsonResponse({'status': True,
                             'message': "file uploaded",
                             'data': uploaded}, status=200)


def id_generator(size=8,
                 chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    return uuid4().hex + str(datetime.now().time().microsecond)


def upload_gcp(file, path, acl="public-read"):
    try:

        try:
            # with os.fdopen(fd, 'w') as tmp:
            #     tmp.write(jsonfile)
            cred_path = '/HuntProject/techstriker-devs.json'
            credentials = service_account.Credentials.from_service_account_file(cred_path)
            storage_client = storage.Client(credentials=credentials)
            bucket = storage_client.get_bucket(BUCKET)
            blob = bucket.blob(path)
            blob.upload_from_file(file)

            # returns a public url
            return blob.public_url

        except Exception as e:
            print("Something Happened: ", e)
            return JsonResponse({'uploaded': False,
                                 'error': "s3 error"
                                 })

    except Exception as e:
        print("Something Happened: ", e)
        return JsonResponse({'uploaded': False,
                             'error': "s3 error"
                             })
    # path = f"{os.environ.get('S3_PATH')}{os.environ.get('CDN_PATH')}{path}"


