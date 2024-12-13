import os
import json
from django.db import connection, IntegrityError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User

from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.authentication import JWTAuthentication

import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv() 

from .models import UserCSVFile
from .serializers import UserSerializer, UserCSVFileSerializer
from .utils import create_table_from_csv, get_table_data
from django.views.decorators.csrf import csrf_exempt


# Similar authentication views as in your original code...


# --------------------------------- Home ---------------------------------

@api_view(['GET'])
@csrf_exempt 
def home(request):
    return Response({'message': 'Api/'})

# --------------------------------- User ---------------------------------

@api_view(['GET'])
@csrf_exempt 
@authentication_classes([JWTAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def get_user(request):
    user = get_object_or_404(User, id=request.user.id)
    serializer = UserSerializer(user)
    return Response(serializer.data)

# --------------------------------- Authentication ---------------------------------

@api_view(['POST'])
@csrf_exempt 
def user_login(request):
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response({'detail': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = get_object_or_404(User, email=email)
        if user.check_password(password):
            token, _ = Token.objects.get_or_create(user=user)
            serializer = UserSerializer(user)
            return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_200_OK)
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@csrf_exempt 
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response({'detail': 'Token is valid'}, status=status.HTTP_200_OK)

@api_view(['POST'])
@csrf_exempt 
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def user_logout(request):
    try:
        token_key = request.headers.get('Authorization').split(' ')[1]
        token = Token.objects.get(key=token_key)
        token.delete()
        return Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)
    except Token.DoesNotExist:
        return Response({'detail': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@csrf_exempt 
def user_register(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.set_password(request.data.get('password'))
        user.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'user': serializer.data}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@csrf_exempt 
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def upload_csv(request):
    if 'file' not in request.FILES:
        return JsonResponse({"error": "CSV file is required"}, status=400)
    
    csv_file = request.FILES['file']
    user = request.user
    
    try:
        # Verify it's a CSV
        if not csv_file.name.endswith('.csv'):
            return JsonResponse({"error": "Only CSV files are allowed"}, status=400)
        
        # Create table and get metadata
        table_name, columns_info = create_table_from_csv(csv_file, user, csv_file.name)
        
        # Save file metadata
        csv_file_record = UserCSVFile.objects.get_or_create(
            user=user,
            filename=csv_file.name,
            table_name=table_name,
            columns=columns_info
        )
        
        return JsonResponse({
            "message": "CSV uploaded successfully",
            "table_name": table_name,
            "columns": columns_info
        }, status=200)
    
    except Exception as e:
        return JsonResponse({
            "error": "Failed to process CSV", 
            "message": str(e)
        }, status=400)

@api_view(['GET'])
@csrf_exempt 
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def get_user_csv_files(request):
    """
    Get list of CSV files uploaded by the user
    """
    csv_files = UserCSVFile.objects.filter(user=request.user)
    serializer = UserCSVFileSerializer(csv_files, many=True)
    return Response(serializer.data)

class CustomQueryView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        table_name = request.data.get('table_name')
        prompt = request.data.get('prompt')

        if not table_name or not prompt:
            return Response({'error': 'Table name and prompt are required'}, status=400)

        try:
            import google.generativeai as genai

            genai.configure(api_key="AIzaSyCtobsZAKGo1xHLpAFIptHnpSTPOSr7weU")
            model = genai.GenerativeModel("gemini-1.5-flash")

            # Get table columns dynamically
            csv_file = UserCSVFile.objects.get(table_name=table_name, user=request.user)
            columns_str = ', '.join([col['name'] for col in csv_file.columns])

            system_message = (
                'You are a Data Scientist Who writes SQL queries for PostgreSQL. when a natural language request is given you will understand the requirement and write the Postgres SQL query'
                f'The table name is {table_name}. '
                f'The columns of this table are: {columns_str}. '
                'Remember, while writing a query, put the colum names in "". Example: SELECT "PRICE" FROM TABLE;. '
                'The query should be a single line query. Please do not use new line characters'
                'Send the response in the following JSON format Recipe = { query: <Query>}.'
                'Return Recipe'
                'Please dont start the response with `json` word'
                'Here is the Natural language prompt: '
            )

            response = model.generate_content(
                system_message+prompt
            )

            generated_text = response.text.strip('`').replace('json\n', '').replace('\n```', '')
            data = json.loads(generated_text)
            sql_query = data["query"]

            with connection.cursor() as cursor:
                cursor.execute(sql_query)
                columns = [col[0] for col in cursor.description]
                results = [dict(zip(columns, row)) for row in cursor.fetchall()]

            return Response({'custom_query_results': results})

        except Exception as e:
            return Response({'error': str(e)}, status=500)
        

class DynamicTableQueryView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Handle aggregate and search queries for user's uploaded CSV tables
        """
        query_params = request.query_params
        
        if not query_params:
            return Response({'error': 'No query parameters provided'}, status=400)

        table_name = query_params.get('table_name')
        field = query_params.get('field')
        value = query_params.get('value')
        operator = query_params.get('operator', '=')

        if not table_name or not field:
            return Response({'error': 'Table name and field are required'}, status=400)

        try:
            # Verify the table belongs to the user
            csv_file = UserCSVFile.objects.get(table_name=table_name, user=request.user)
            
            # Validate field exists in the table's columns
            field_exists = any(col['name'] == field for col in csv_file.columns)
            if not field_exists:
                return Response({'error': f'Invalid field: {field}'}, status=400)

            # Determine field type
            field_type = next((col['type'] for col in csv_file.columns if col['name'] == field), None)

            # Perform search
            search_results = self._get_search_results(table_name, field, operator, value) if value is not None else None

            # Perform aggregate results
            aggregate_results = self._get_aggregate_results(table_name, field, field_type)

            # Perform constrained aggregate results
            constrained_aggregate_results = None
            if field_type in ['int64', 'float64'] and value is not None:
                constrained_aggregate_results = self._get_constrained_aggregate_results(
                    table_name, field, operator, value
                )

            return Response({
                'search_results': search_results,
                'aggregate_results': aggregate_results,
                'constrained_aggregate_results': constrained_aggregate_results
            })

        except UserCSVFile.DoesNotExist:
            return Response({'error': 'Table not found or unauthorized'}, status=403)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

    def _get_search_results(self, table_name, field, operator, value):
        """
        Perform search results for a given table and field
        """
        query = f"SELECT * FROM {table_name} WHERE "
        
        if operator == '=':
            query += f'"{field}" = {value}' if type(value) is str else f'"{field}" = {value}'

        elif operator == '>':
            query += f'"{field}" > {value}'
        elif operator == '>=':
            query += f'"{field}" >= {value}'
        elif operator == '<':
            query += f'"{field}" < {value}'
        elif operator == '<=':
            query += f'"{field}" <= {value}'
        else:
            raise ValueError(f"Unsupported operator: {operator}")

        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        return results

    def _get_aggregate_results(self, table_name, field, field_type):
        """
        Compute aggregate results for numeric fields
        """
        if field_type not in ['int64', 'float64']:
            return None
        query = f"""
                SELECT 
                    AVG("{field}") as avg,
                    MAX("{field}") as max,
                    MIN("{field}") as min,
                    SUM("{field}") as sum,
                    COUNT("{field}") as count
                FROM {table_name}
            """
        with connection.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()
            columns = ['avg', 'max', 'min', 'sum', 'count']
            return dict(zip(columns, result))

    def _get_constrained_aggregate_results(self, table_name, field, operator, value):
        """
        Compute aggregate results with constraints
        """
        query = f"""
            SELECT 
                AVG("{field}") as avg,
                MAX("{field}") as max,
                MIN("{field}") as min,
                SUM("{field}") as sum,
                COUNT("{field}") as count
            FROM {table_name}
            WHERE "{field}" {operator} {value}
        """

        with connection.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()
            columns = ['avg', 'max', 'min', 'sum', 'count']
            return dict(zip(columns, result))