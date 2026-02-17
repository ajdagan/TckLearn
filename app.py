from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
import stripe
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
SUPABASE_URL = os.getenv('SUPABASE_URL', 'YOUR_SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', 'YOUR_SUPABASE_ANON_KEY')
STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY', 'YOUR_STRIPE_SECRET_KEY')
JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-this')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', '')

# Initialize clients
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
stripe.api_key = STRIPE_SECRET_KEY

# Pricing configuration
PRICING = {
    'weekly': {
        'amount': 2900,  # $29.00 in cents
        'interval': 'week',
        'name': 'Weekly Plan'
    },
    'monthly': {
        'amount': 9900,  # $99.00 in cents
        'interval': 'month',
        'name': 'Monthly Plan'
    },
    'yearly': {
        'amount': 99900,  # $999.00 in cents
        'interval': 'year',
        'name': 'Yearly Plan'
    }
}

# JWT token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = supabase.table('users').select('*').eq('id', data['user_id']).execute()
            
            if not current_user.data:
                return jsonify({'error': 'User not found'}), 401
            
            request.current_user = current_user.data[0]
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        
        if not all([name, email, password]):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Check if user exists
        existing_user = supabase.table('users').select('*').eq('email', email).execute()
        if existing_user.data:
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user in Supabase Auth
        auth_response = supabase.auth.sign_up({
            'email': email,
            'password': password
        })
        
        if auth_response.user:
            # Create user profile
            user_data = {
                'id': auth_response.user.id,
                'name': name,
                'email': email,
                'subscription_status': 'inactive',
                'created_at': datetime.utcnow().isoformat()
            }
            
            supabase.table('users').insert(user_data).execute()
            
            # Generate JWT token
            token = jwt.encode({
                'user_id': auth_response.user.id,
                'exp': datetime.utcnow() + timedelta(days=30)
            }, JWT_SECRET, algorithm='HS256')
            
            return jsonify({
                'message': 'Registration successful',
                'token': token,
                'user': {
                    'id': auth_response.user.id,
                    'name': name,
                    'email': email
                }
            }), 201
        else:
            return jsonify({'error': 'Registration failed'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Authenticate with Supabase
        auth_response = supabase.auth.sign_in_with_password({
            'email': email,
            'password': password
        })
        
        if auth_response.user:
            # Get user profile
            user_profile = supabase.table('users').select('*').eq('id', auth_response.user.id).execute()
            
            if user_profile.data:
                user = user_profile.data[0]
                
                # Generate JWT token
                token = jwt.encode({
                    'user_id': auth_response.user.id,
                    'exp': datetime.utcnow() + timedelta(days=30)
                }, JWT_SECRET, algorithm='HS256')
                
                return jsonify({
                    'message': 'Login successful',
                    'token': token,
                    'user': {
                        'id': user['id'],
                        'name': user['name'],
                        'email': user['email'],
                        'subscription_status': user.get('subscription_status', 'inactive')
                    }
                }), 200
        
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['GET'])
@token_required
def get_profile():
    try:
        user = request.current_user
        return jsonify({
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'subscription_status': user.get('subscription_status', 'inactive'),
                'subscription_plan': user.get('subscription_plan'),
                'subscription_end_date': user.get('subscription_end_date')
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Subscription Routes
@app.route('/api/subscription/create', methods=['POST'])
@token_required
def create_subscription():
    try:
        data = request.get_json()
        plan_type = data.get('planType', 'monthly')
        user = request.current_user
        
        if plan_type not in PRICING:
            return jsonify({'error': 'Invalid plan type'}), 400
        
        plan = PRICING[plan_type]
        
        # Create Stripe Checkout Session
        checkout_session = stripe.checkout.Session.create(
            customer_email=user['email'],
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'TckLearn {plan["name"]}',
                        'description': f'Live IT & Computing courses - {plan["name"]}'
                    },
                    'unit_amount': plan['amount'],
                    'recurring': {
                        'interval': plan['interval']
                    }
                },
                'quantity': 1
            }],
            mode='subscription',
            success_url=f'{request.host_url}?session_id={{CHECKOUT_SESSION_ID}}&success=true',
            cancel_url=f'{request.host_url}?canceled=true',
            metadata={
                'user_id': user['id'],
                'plan_type': plan_type
            }
        )
        
        return jsonify({
            'sessionId': checkout_session.id,
            'url': checkout_session.url
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subscription/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        return jsonify({'error': 'Invalid signature'}), 400
    
    # Handle different event types
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session['metadata']['user_id']
        plan_type = session['metadata']['plan_type']
        
        # Calculate subscription end date
        if plan_type == 'weekly':
            end_date = datetime.utcnow() + timedelta(weeks=1)
        elif plan_type == 'monthly':
            end_date = datetime.utcnow() + timedelta(days=30)
        else:  # yearly
            end_date = datetime.utcnow() + timedelta(days=365)
        
        # Update user subscription
        supabase.table('users').update({
            'subscription_status': 'active',
            'subscription_plan': plan_type,
            'subscription_end_date': end_date.isoformat(),
            'stripe_customer_id': session.get('customer'),
            'stripe_subscription_id': session.get('subscription')
        }).eq('id', user_id).execute()
        
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        # Update user subscription to inactive
        supabase.table('users').update({
            'subscription_status': 'inactive'
        }).eq('stripe_subscription_id', subscription['id']).execute()
    
    return jsonify({'status': 'success'}), 200

# Classes Routes
@app.route('/api/classes/upcoming', methods=['GET'])
@token_required
def get_upcoming_classes():
    try:
        user = request.current_user
        
        # Check if user has active subscription
        if user.get('subscription_status') != 'active':
            return jsonify({'classes': [], 'message': 'No active subscription'}), 200
        
        # Get upcoming classes
        classes = supabase.table('classes').select('*').gte(
            'date', datetime.utcnow().isoformat()
        ).order('date').limit(10).execute()
        
        return jsonify({'classes': classes.data}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/create', methods=['POST'])
@token_required
def create_class():
    try:
        data = request.get_json()
        
        # Admin check would go here
        
        class_data = {
            'title': data.get('title'),
            'description': data.get('description'),
            'category': data.get('category'),
            'instructor': data.get('instructor'),
            'date': data.get('date'),
            'time': data.get('time'),
            'duration': data.get('duration', 60),
            'meeting_link': data.get('meetingLink'),
            'max_students': data.get('maxStudents', 50),
            'created_at': datetime.utcnow().isoformat()
        }
        
        result = supabase.table('classes').insert(class_data).execute()
        
        return jsonify({'message': 'Class created successfully', 'class': result.data[0]}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes/<class_id>/enroll', methods=['POST'])
@token_required
def enroll_class(class_id):
    try:
        user = request.current_user
        
        # Check subscription
        if user.get('subscription_status') != 'active':
            return jsonify({'error': 'Active subscription required'}), 403
        
        # Check if already enrolled
        existing = supabase.table('enrollments').select('*').eq(
            'user_id', user['id']
        ).eq('class_id', class_id).execute()
        
        if existing.data:
            return jsonify({'error': 'Already enrolled'}), 400
        
        # Create enrollment
        enrollment = {
            'user_id': user['id'],
            'class_id': class_id,
            'enrolled_at': datetime.utcnow().isoformat()
        }
        
        supabase.table('enrollments').insert(enrollment).execute()
        
        return jsonify({'message': 'Enrolled successfully'}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
