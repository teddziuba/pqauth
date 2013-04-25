import json

from django.http import HttpResponse
from django.contrib.auth.decorators import login_required


@login_required
def access_controlled_endpoint(request):
    response = {"your_email": request.user.email,
                "secret_message": "Don't forget to drink your Ovaltine."}
    return HttpResponse(json.dumps(response), mimetype="application/json")

