import os
import pandas as pd
from django.db import connection
from sqlalchemy import create_engine
from django.conf import settings

def create_table_from_csv(csv_file, user, filename):
    """
    Create a PostgreSQL table from CSV and track file metadata
    """
    # Read CSV file
    df = pd.read_csv(csv_file)
    first_filename = filename.split(".")[0]
    # Generate unique table name
    table_name = f"user_{user.id}_csv_{first_filename}".lower().replace('-', '_')
    
    # SQLAlchemy engine for pandas to_sql
    engine = create_engine("postgresql" + '://' +
                           settings.DATABASES['default']['USER'] + ':' +
                           settings.DATABASES['default']['PASSWORD'] + '@' +
                           settings.DATABASES['default']['HOST'] + ':' +
                           settings.DATABASES['default']['PORT'] + '/' +
                           settings.DATABASES['default']['NAME'])
    
    # Write dataframe to PostgreSQL
    df.to_sql(name=table_name, con=engine, if_exists='replace')
    
    # Create column metadata
    columns_info = [
        {
            'name': col,
            'type': str(df[col].dtype)
        } for col in df.columns
    ]
    
    return table_name, columns_info

def get_table_data(table_name, limit=100):
    """
    Retrieve data from a specific table
    """
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT * FROM "{table_name}" LIMIT {limit}')
        columns = [col[0] for col in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    return results

