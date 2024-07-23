# Uncomment the imports before you add the code
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from django.views.generic import TemplateView
from . import views

app_name = 'djangoapp'
urlpatterns = [
    # # path for registration
    path(route='register', view=views.registration, name='register'),
    
    # path for login
    path(route='login', view=views.login_user, name='login'),
    path(route='logout', view=views.logout_request, name='logout'),

    # path for dealer reviews view
    path('dealerships/', views.get_dealerships, name='get_dealerships'),
    path('dealership/<int:dealer_id>/', views.get_dealer_details, name='get_dealer_details'),
    
    # path for add a review view
    path('reviews/<int:dealer_id>/', views.get_dealer_reviews, name='get_dealer_reviews'),
    path('add_review/', views.add_review, name='add_review'),
    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
