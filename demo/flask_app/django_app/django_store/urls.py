"""URL Configuration for django_store vulnerable application."""

from django.urls import path
from django_store import views

urlpatterns = [
    path('', views.index_view, name='index'),
    path('search/', views.search_view, name='search'),
    path('api/orders/<int:order_id>/', views.order_detail_view, name='order_detail'),
    path('comments/', views.comment_submit_view, name='comments'),
    path('tools/ping/', views.diagnostic_ping_view, name='diagnostic_ping'),
    path('api/calculator/', views.discount_calculator_view, name='discount_calculator'),
    path('api/token/', views.generate_session_token_view, name='token_generator'),
]
