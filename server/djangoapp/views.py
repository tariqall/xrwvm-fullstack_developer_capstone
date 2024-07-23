# Uncomment the required imports before adding the code

from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import logout
from django.contrib import messages
from datetime import datetime

from django.http import JsonResponse
from django.contrib.auth import login, authenticate
import logging
import json
from django.views.decorators.csrf import csrf_exempt
from .models import Dealership, Review
from .populate import initiate


# Get an instance of a logger
logger = logging.getLogger(__name__)


# Create your views here.

# Create a `login_request` view to handle sign in request
@csrf_exempt
def login_user(request):
    # Get username and password from request.POST dictionary
    data = json.loads(request.body)
    username = data['userName']
    password = data['password']
    # Try to check if provide credential can be authenticated
    user = authenticate(username=username, password=password)
    data = {"userName": username}
    if user is not None:
        # If user is valid, call login method to login current user
        login(request, user)
        data = {"userName": username, "status": "Authenticated"}
    return JsonResponse(data)

# Create a `logout_request` view to handle sign out request
def logout_request(request):
    logout(request)
    data = {"userName":""}
    return JsonResponse(data)

# Create a `registration` view to handle sign up request
@csrf_exempt
def registration(request):
    context = {}

    data = json.loads(request.body)
    username = data['userName']
    password = data['password']
    first_name = data['firstName']
    last_name = data['lastName']
    email = data['email']
    username_exist = False
    email_exist = False
    try:
        # Check if user already exists
        User.objects.get(username=username)
        username_exist = True
    except:
        # If not, simply log this is a new user
        logger.debug("{} is new user".format(username))

    # If it is a new user
    if not username_exist:
        # Create user in auth_user table
        user = User.objects.create_user(username=username, first_name=first_name, last_name=last_name,password=password, email=email)
        # Login the user and redirect to list page
        login(request, user)
        data = {"userName":username,"status":"Authenticated"}
        return JsonResponse(data)
    else :
        data = {"userName":username,"error":"Already Registered"}
        return JsonResponse(data)

# # Update the `get_dealerships` view to render the index page with
# a list of dealerships
def get_dealerships(request):
    try:
        dealerships = Dealership.objects.all()
        dealerships_list = list(dealerships.values())
        return JsonResponse(dealerships_list, safe=False)
    except Exception as e:
        logger.error(f"Error fetching dealerships: {e}")
        return JsonResponse({"error": "Error fetching dealerships"}, status=500)

# Create a `get_dealer_reviews` view to render the reviews of a dealer
def get_dealer_reviews(request, dealer_id):
    try:
        reviews = Review.objects.filter(dealership=dealer_id)
        reviews_list = list(reviews.values())
        return JsonResponse(reviews_list, safe=False)
    except Exception as e:
        logger.error(f"Error fetching reviews for dealer {dealer_id}: {e}")
        return JsonResponse({"error": f"Error fetching reviews for dealer {dealer_id}"}, status=500)

# Create a `get_dealer_details` view to render the dealer details
def get_dealer_details(request, dealer_id):
    try:
        dealer = get_object_or_404(Dealership, pk=dealer_id)
        dealer_data = {
            "id": dealer.id,
            "name": dealer.name,
            "state": dealer.state,
            "address": dealer.address,
            "zip": dealer.zip,
            "phone": dealer.phone,
        }
        return JsonResponse(dealer_data)
    except Exception as e:
        logger.error(f"Error fetching dealer details for dealer {dealer_id}: {e}")
        return JsonResponse({"error": f"Error fetching dealer details for dealer {dealer_id}"}, status=500)

# Create a `add_review` view to submit a review
def add_review(request):
    try:
        data = json.loads(request.body)
        dealer_id = data.get('dealership')
        review = Review(
            dealership=dealer_id,
            name=data.get('name'),
            review=data.get('review'),
            purchase=data.get('purchase'),
            purchase_date=data.get('purchase_date'),
            car_make=data.get('car_make'),
            car_model=data.get('car_model'),
            car_year=data.get('car_year'),
        )
        review.save()
        return JsonResponse({"message": "Review added successfully"}, status=201)
    except Exception as e:
        logger.error(f"Error adding review: {e}")
        return JsonResponse({"error": "Error adding review"}, status=500)
