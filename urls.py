from django.urls import path
from . import views

urlpatterns = [
    # Authentication routes
    path('login/', views.user_login, name='login'),
    path('register/', views.user_register, name='register'),
    path('logout/', views.user_logout, name='logout'),
    path('test-token/', views.test_token, name='test-token'),
    
    # CSV related routes
    path('upload/', views.upload_csv, name='upload'),
    path('csv/', views.get_user_csv_files, name='csv'),
    
    # Custom query route
    path('custom-query/', views.CustomQueryView.as_view(), name='custom-query'),
    path('query/', views.DynamicTableQueryView.as_view(), name='query'),

]
